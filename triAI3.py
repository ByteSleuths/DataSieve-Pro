import os
import re
import json
import csv
import glob
import logging
import sqlite3
import pandas as pd
import concurrent.futures
from collections import defaultdict
import time
import pyximport; pyximport.install()
import sys
import importlib.util
import ipaddress
import email_validator
import uuid as uuid_lib
import subprocess
import multiprocessing
from functools import lru_cache
import signal
import hashlib
from tqdm import tqdm

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Logger spécifique pour le rapport de qualité
quality_logger = logging.getLogger("quality_report")
quality_handler = logging.FileHandler("quality_report.log")
quality_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
quality_logger.addHandler(quality_handler)
quality_logger.setLevel(logging.INFO)

# Configuration globale
CONFIG = {
    "email": {
        "min_length": 5,
        "max_length": 254,
        "blacklisted_domains": ["example.com", "test.com", "temporary.com", "disposable.email"],
    },
    "user": {
        "min_length": 2,  # Réduit pour capturer plus d'utilisateurs
        "max_length": 100,  # Augmenté pour plus de flexibilité
        "blacklisted_names": ["admin", "test", "user", "guest", "anonymous"],
    },
    "password": {
        "min_length": 4,  # Réduit pour capturer plus de mots de passe
        "max_length": 200,
    },
    "ip": {
        "exclude_private": True,
        "exclude_loopback": True,
        "exclude_link_local": True,
    },
    "uuid": {
        "validate_format": True,
    },
    "quality_thresholds": {
        "min_fields_filled": 2,  # Au moins 2 champs remplis pour considérer un enregistrement valide
    },
    "performance": {
        "chunk_size": 10000,
        "max_workers": min(32, os.cpu_count() * 2),
        "memory_limit": 0.8,  # 80% de la mémoire disponible
        "retry_attempts": 3,
        "batch_size": 5000,
    },
    "limits": {
        "max_unique_users": 20014280,  # Limite stricte d'utilisateurs uniques
    }
}

# Statistiques de qualité partagées entre processus
QUALITY_STATS = {
    "total_processed": multiprocessing.Value('i', 0),
    "valid_records": multiprocessing.Value('i', 0),
    "rejected_records": multiprocessing.Value('i', 0),
    "duplicates_removed": multiprocessing.Value('i', 0),
    "invalid_emails": multiprocessing.Value('i', 0),
    "blacklisted_emails": multiprocessing.Value('i', 0),
    "invalid_usernames": multiprocessing.Value('i', 0),
    "blacklisted_usernames": multiprocessing.Value('i', 0),
    "invalid_passwords": multiprocessing.Value('i', 0),
    "invalid_ips": multiprocessing.Value('i', 0),
    "invalid_uuids": multiprocessing.Value('i', 0),
    "cleaned_emails": multiprocessing.Value('i', 0),
    "cleaned_usernames": multiprocessing.Value('i', 0),
    "normalized_ips": multiprocessing.Value('i', 0),
    "sha_passwords_found": multiprocessing.Value('i', 0),
    "start_time": time.time(),
    "files_processed": multiprocessing.Value('i', 0),
    "files_with_errors": multiprocessing.Value('i', 0),
    "records_by_source": defaultdict(int),
    "unique_users_count": multiprocessing.Value('i', 0),
}

# Expressions régulières améliorées pour une meilleure détection
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', re.IGNORECASE)
PASSWORD_REGEX = re.compile(r'(?:password[:=]?\s*|pwd[:=]?\s*|pass[:=]?\s*|mdp[:=]?\s*)([\w!@#$%^&*()-_+=]{3,100})', re.IGNORECASE)
USERNAME_REGEX = re.compile(r'(?:username[:=]?\s*|user[:=]?\s*|login[:=]?\s*|pseudo[:=]?\s*|name[:=]?\s*)([\w.\-@+]{2,50})', re.IGNORECASE)
UUID_REGEX = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)
IP_REGEX = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
TLD_REGEX = re.compile(r'\.(com|net|org|edu|gov|mil|int|fr|uk|de|jp|cn|ru|br|in|au|ca|it|nl|es|se|no|fi|dk|ch|at|be|pl|pt|gr|ie|nz|za|mx|ar|cl|co|pe|ve|tr|sa|ae|eg|th|sg|my|ph|vn|id|kr|tw|hk|il|us|eu|info|biz|io|dev|app|tech|online|store|blog|site|xyz|me|co\.uk|co\.jp|co\.in|com\.au|co\.nz|or\.jp|ne\.jp|ac\.jp|ac\.uk|ac\.nz|edu\.au|gov\.au|org\.au)$', re.IGNORECASE)
SHA_HASH_REGEX = re.compile(r'(\$SHA\$[a-f0-9]+\$[a-f0-9]+)', re.IGNORECASE)
SHA_LINE_REGEX = re.compile(r'^([^:]+):(\$SHA\$[a-f0-9]+\$[a-f0-9]+):(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$')
MD5_REGEX = re.compile(r'[a-f0-9]{32}', re.IGNORECASE)
BCRYPT_REGEX = re.compile(r'\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9./]{53}', re.IGNORECASE)

# Caches pour optimiser les validations répétitives
email_validation_cache = {}
username_validation_cache = {}
password_validation_cache = {}
ip_validation_cache = {}
uuid_validation_cache = {}

# Variables de contrôle
interrupted = False
limit_reached = False

def signal_handler(sig, frame):
    """Gestionnaire de signal pour arrêter proprement le traitement"""
    global interrupted
    logger.info("Interruption détectée, arrêt en cours...")
    interrupted = True

signal.signal(signal.SIGINT, signal_handler)

# Création du module Cython pour accélérer le traitement
with open('data_processor.pyx', 'w', encoding='utf-8') as f:
    f.write('''
import re
import csv
import hashlib
import ipaddress
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Any, Optional
from libc.string cimport strlen, strchr, strstr, memcpy
from cpython.dict cimport PyDict_GetItem, PyDict_SetItem, PyDict_Contains
from cpython.set cimport PySet_Add, PySet_Contains
from cpython.bytes cimport PyBytes_FromStringAndSize
from cpython.unicode cimport PyUnicode_FromString

# Expressions régulières compilées pour performance
cdef object EMAIL_REGEX = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+', re.IGNORECASE)
cdef object PASSWORD_REGEX = re.compile(r'(?:password[:=]?\\s*|pwd[:=]?\\s*|pass[:=]?\\s*|mdp[:=]?\\s*)([\w!@#$%^&*()-_+=]{3,100})', re.IGNORECASE)
cdef object USERNAME_REGEX = re.compile(r'(?:username[:=]?\\s*|user[:=]?\\s*|login[:=]?\\s*|pseudo[:=]?\\s*|name[:=]?\\s*)([\w.\\-@+]{2,50})', re.IGNORECASE)
cdef object UUID_REGEX = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)
cdef object IP_REGEX = re.compile(r'(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})')
cdef object TLD_REGEX = re.compile(r'\\.(com|net|org|edu|gov|mil|int|fr|uk|de|jp|cn|ru|br|in|au|ca)', re.IGNORECASE)
cdef object SHA_HASH_REGEX = re.compile(r'(\\$SHA\\$[a-f0-9]+\\$[a-f0-9]+)', re.IGNORECASE)
cdef object SHA_LINE_REGEX = re.compile(r'^([^:]+):(\\$SHA\\$[a-f0-9]+\\$[a-f0-9]+):(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})$')
cdef object MD5_REGEX = re.compile(r'[a-f0-9]{32}', re.IGNORECASE)
cdef object BCRYPT_REGEX = re.compile(r'\\$2[ayb]\\$[0-9]{2}\\$[A-Za-z0-9./]{53}', re.IGNORECASE)

cdef class DataProcessor:
    cdef public dict merged_data
    cdef public set processed_keys
    cdef public dict email_index
    cdef public dict user_index
    cdef public int unique_count
    cdef public int max_unique_users
    
    def __init__(self, max_unique_users=20014280):
        self.merged_data = {}
        self.processed_keys = set()
        self.email_index = {}
        self.user_index = {}
        self.unique_count = 0
        self.max_unique_users = max_unique_users
    
    cpdef bint merge_record(self, dict record, str source_file="") except? -1:
        """Fusionne un enregistrement dans la base de données unifiée"""
        cdef str email, user, key, field
        cdef dict existing
        
        # Vérifier si l'enregistrement contient un email ou un nom d'utilisateur
        if not record.get("email") and not record.get("user"):
            return False
            
        # Créer une clé unique basée sur l'email et/ou le nom d'utilisateur
        if record.get("email"):
            email = record["email"].lower()
            
            # Vérifier si l'email est valide
            if not EMAIL_REGEX.match(email) or not TLD_REGEX.search(email):
                # Si l'email n'est pas valide mais qu'on a un nom d'utilisateur, on continue
                if not record.get("user"):
                    return False
            else:
                # Si l'email existe déjà dans notre index
                if email in self.email_index:
                    existing_key = self.email_index[email]
                    existing = self.merged_data.get(existing_key)
                    if existing:
                        # Mettre à jour les champs manquants
                        for field in ["user", "password", "uuid", "ip"]:
                            if record.get(field) and not existing.get(field):
                                existing[field] = record[field]
                        return True
        
        # Si nous avons un nom d'utilisateur
        if record.get("user"):
            user = record["user"].lower()
            
            # Si le nom d'utilisateur existe déjà dans notre index
            if user in self.user_index:
                existing_key = self.user_index[user]
                existing = self.merged_data.get(existing_key)
                if existing:
                    # Mettre à jour les champs manquants
                    for field in ["email", "password", "uuid", "ip"]:
                        if record.get(field) and not existing.get(field):
                            existing[field] = record[field]
                    return True
        
        # Si nous arrivons ici, c'est un nouvel enregistrement
        # Vérifier si nous avons atteint la limite d'utilisateurs uniques
        if self.unique_count >= self.max_unique_users:
            return False
            
        # Créer une clé unique pour cet enregistrement
        if record.get("email") and record.get("user"):
            key = f"{record['email'].lower()}:{record['user'].lower()}"
        elif record.get("email"):
            key = f"email:{record['email'].lower()}"
        elif record.get("user"):
            key = f"user:{record['user'].lower()}"
        else:
            return False
            
        # Ajouter l'enregistrement à notre base
        if key not in self.processed_keys:
            self.processed_keys.add(key)
            self.merged_data[key] = {
                "email": record.get("email", ""),
                "user": record.get("user", ""),
                "password": record.get("password", ""),
                "uuid": record.get("uuid", ""),
                "ip": record.get("ip", "")
            }
            
            # Mettre à jour nos index
            if record.get("email"):
                self.email_index[record["email"].lower()] = key
            if record.get("user"):
                self.user_index[record["user"].lower()] = key
                
            self.unique_count += 1
            return True
            
        return False
    
    cpdef dict extract_from_txt_line(self, str line):
        """Extrait les informations d'une ligne de texte"""
        cdef dict result = {"user": "", "email": "", "password": "", "uuid": "", "ip": ""}
        cdef object match
        
        line = line.strip()
        if not line:
            return None
        
        # Vérifier d'abord si la ligne correspond au format SHA spécifique
        match = SHA_LINE_REGEX.match(line)
        if match:
            result["user"] = match.group(1)
            result["password"] = match.group(2)
            result["ip"] = match.group(3)
            return result
        
        # Recherche d'email
        email_matches = EMAIL_REGEX.findall(line)
        if email_matches:
            for email in email_matches:
                # Vérifier que l'email a un TLD valide
                if TLD_REGEX.search(email):
                    result["email"] = email
                    break
        
        # Si pas d'email trouvé, essayer d'extraire un email potentiel
        if not result["email"]:
            potential_email = self._extract_potential_email(line)
            if potential_email and EMAIL_REGEX.match(potential_email) and TLD_REGEX.search(potential_email):
                result["email"] = potential_email
        
        # Recherche de hash SHA ou autres formats de mot de passe
        match = SHA_HASH_REGEX.search(line)
        if match:
            result["password"] = match.group(1)
        else:
            match = BCRYPT_REGEX.search(line)
            if match:
                result["password"] = match.group(0)
            else:
                match = MD5_REGEX.search(line)
                if match and len(line) < 100:  # Éviter de capturer des hashes aléatoires dans de longues lignes
                    result["password"] = match.group(0)
                else:
                    # Recherche de mot de passe standard
                    match = PASSWORD_REGEX.search(line)
                    if match:
                        result["password"] = match.group(1)
                    else:
                        potential_password = self._extract_potential_password(line)
                        if potential_password:
                            result["password"] = potential_password
        
        # Recherche de nom d'utilisateur
        match = USERNAME_REGEX.search(line)
        if match and match.group(1).lower() not in ["null", "insert", "complete", "undefined", "none"]:
            result["user"] = match.group(1)
        else:
            potential_user = self._extract_potential_username(line, result["email"])
            if potential_user:
                result["user"] = potential_user
        
        # Recherche d'UUID
        match = UUID_REGEX.search(line)
        if match:
            result["uuid"] = match.group(0)
        
        # Recherche d'IP
        match = IP_REGEX.search(line)
        if match:
            ip = match.group(1)
            # Vérifier que l'IP est valide
            try:
                ip_obj = ipaddress.ip_address(ip)
                result["ip"] = ip
            except:
                pass
        
        # Si nous n'avons ni email ni utilisateur, l'enregistrement n'est pas utile
        if not result["email"] and not result["user"] and not result["password"]:
            return None
            
        return result
        
    cdef str _extract_potential_email(self, str line):
        """Extrait un email potentiel d'une ligne de texte"""
        cdef int i, at_pos = -1, dot_pos = -1
        cdef str potential_email = ""
        
        # Méthode simple: diviser par espaces
        parts = line.split()
        for part in parts:
            if '@' in part and '.' in part.split('@')[1]:
                # Nettoyer la partie pour obtenir un email valide
                cleaned = re.sub(r'[^a-zA-Z0-9_.+\\-@]', '', part)
                if EMAIL_REGEX.match(cleaned):
                    return cleaned
        
        # Méthode alternative si la première échoue
        for i in range(len(line)):
            if line[i] == '@':
                at_pos = i
            elif line[i] == '.' and at_pos != -1 and i > at_pos:
                dot_pos = i
                break
        
        if at_pos != -1 and dot_pos != -1:
            start = max(0, at_pos - 30)
            end = min(len(line), dot_pos + 10)
            potential_email = line[start:end]
            potential_email = re.sub(r'[^a-zA-Z0-9_.+\\-@]', '', potential_email)
            if '@' in potential_email and '.' in potential_email.split('@')[1]:
                if TLD_REGEX.search(potential_email):
                    return potential_email
        
        return ""
        
    cdef str _extract_potential_password(self, str line):
        """Extrait un mot de passe potentiel d'une ligne de texte"""
        # Vérifier d'abord les hashes connus
        match = SHA_HASH_REGEX.search(line)
        if match:
            return match.group(1)
            
        match = BCRYPT_REGEX.search(line)
        if match:
            return match.group(0)
            
        match = MD5_REGEX.search(line)
        if match and len(line) < 100:  # Éviter de capturer des hashes aléatoires dans de longues lignes
            return match.group(0)
            
        # Recherche par mots-clés
        cdef list password_keywords = ["password", "pass", "pwd", "mot de passe", "passwd", "secret", "mdp"]
        cdef str keyword, lower_line = line.lower()
        cdef int pos
        
        for keyword in password_keywords:
            pos = lower_line.find(keyword)
            if pos != -1:
                after_keyword = line[pos + len(keyword):].strip()
                for sep in [':', '=', ' is ', ' - ', '>', '"', "'"]:
                    sep_pos = after_keyword.find(sep)
                    if sep_pos != -1:
                        potential_pwd = after_keyword[sep_pos + len(sep):].strip()
                        potential_pwd = re.split(r'[\\s,;]', potential_pwd)[0]
                        if len(potential_pwd) >= 3 and len(potential_pwd) <= 200:
                            return potential_pwd
        
        # Recherche de motifs courants de mot de passe - méthode simplifiée
        parts = line.split()
        for part in parts:
            if len(part) >= 6 and len(part) <= 30:
                # Vérifier si le mot ressemble à un mot de passe (mélange de lettres, chiffres, caractères spéciaux)
                if re.search(r'[a-zA-Z]', part) and re.search(r'[0-9]', part):
                    return part
        
        return ""
        
    cdef str _extract_potential_username(self, str line, str email):
        """Extrait un nom d'utilisateur potentiel d'une ligne de texte"""
        # Si nous avons un email, extraire la partie locale
        if email and '@' in email:
            local_part = email.split('@')[0]
            if len(local_part) >= 2 and local_part.lower() not in ["admin", "test", "user", "guest", "anonymous"]:
                return local_part
        
        # Rechercher des mots-clés de nom d'utilisateur
        cdef list username_keywords = ["username", "user", "login", "id", "compte", "account", "name", "pseudo", "identifiant"]
        cdef str keyword, lower_line = line.lower()
        cdef int pos
        
        for keyword in username_keywords:
            pos = lower_line.find(keyword)
            if pos != -1:
                after_keyword = line[pos + len(keyword):].strip()
                for sep in [':', '=', ' is ', ' - ', '>', '"', "'"]:
                    sep_pos = after_keyword.find(sep)
                    if sep_pos != -1:
                        potential_user = after_keyword[sep_pos + len(sep):].strip()
                        potential_user = re.split(r'[\\s,;]', potential_user)[0]
                        if len(potential_user) >= 2 and len(potential_user) <= 50:
                            return potential_user
        
        # Recherche de motifs courants de nom d'utilisateur - méthode simplifiée
        parts = line.split()
        for part in parts:
            if len(part) >= 3 and len(part) <= 20:
                # Vérifier si le mot ressemble à un nom d'utilisateur (lettres et chiffres principalement)
                if re.match(r'^[a-zA-Z0-9._-]+$', part) and part.lower() not in ["null", "undefined", "none", "true", "false"]:
                    return part
        
        return ""
        
    cpdef list process_chunk(self, list lines):
        """Traite un lot de lignes de texte"""
        cdef list results = []
        cdef str line
        cdef dict record
        
        for line in lines:
            record = self.extract_from_txt_line(line)
            if record:
                results.append(record)
        
        return results
''')

# Configuration pour la compilation Cython
with open('setup.py', 'w', encoding='utf-8') as f:
    f.write('''
from setuptools import setup, Extension
from Cython.Build import cythonize
import numpy as np

extensions = [
    Extension("data_processor", 
              ["data_processor.pyx"],
              include_dirs=[np.get_include()],
              extra_compile_args=["-O3", "-march=native", "-ffast-math"],
              language="c++")
]

setup(
    ext_modules=cythonize(extensions, 
                          compiler_directives={
                              'language_level': 3,
                              'boundscheck': False,
                              'wraparound': False,
                              'nonecheck': False,
                              'cdivision': True,
                              'initializedcheck': False,
                              'binding': True,
                          },
                          annotate=True)
)
''')

@lru_cache(maxsize=10000)
def clean_email(email):
    """Nettoie et normalise un email"""
    if not email:
        return ""
    
    # Nettoyage de base
    email = email.strip().lower()
    email = re.sub(r'^["\']|["\']$', '', email)
    
    # Suppression des caractères non valides dans la partie locale
    if len(email) > 254 or re.search(r'[^a-zA-Z0-9_.+-]@', email):
        parts = email.split('@')
        if len(parts) == 2:
            local_part = re.sub(r'[^a-zA-Z0-9_.+-]', '', parts[0])
            domain_part = parts[1]
            email = f"{local_part}@{domain_part}"
    
    # Nettoyage final
    cleaned = re.sub(r'[^\w.@+-]', '', email)
    
    # Vérification de la structure minimale
    if '@' not in cleaned or '.' not in cleaned.split('@')[-1]:
        return ""
    
    # Enregistrement des statistiques
    if cleaned != email:
        with QUALITY_STATS["cleaned_emails"].get_lock():
            QUALITY_STATS["cleaned_emails"].value += 1
    
    return cleaned

@lru_cache(maxsize=10000)
def validate_email(email):
    """Valide un email selon les critères définis"""
    if email in email_validation_cache:
        return email_validation_cache[email]
    
    if not email:
        with QUALITY_STATS["invalid_emails"].get_lock():
            QUALITY_STATS["invalid_emails"].value += 1
        email_validation_cache[email] = False
        return False
    
    # Vérifications de base
    if len(email) < CONFIG["email"]["min_length"] or len(email) > CONFIG["email"]["max_length"]:
        with QUALITY_STATS["invalid_emails"].get_lock():
            QUALITY_STATS["invalid_emails"].value += 1
        email_validation_cache[email] = False
        return False
    
    if not EMAIL_REGEX.match(email):
        with QUALITY_STATS["invalid_emails"].get_lock():
            QUALITY_STATS["invalid_emails"].value += 1
        email_validation_cache[email] = False
        return False
    
    if not TLD_REGEX.search(email):
        with QUALITY_STATS["invalid_emails"].get_lock():
            QUALITY_STATS["invalid_emails"].value += 1
        email_validation_cache[email] = False
        return False
    
    # Vérification des domaines blacklistés
    domain = email.split('@')[-1].lower()
    for blacklisted in CONFIG["email"]["blacklisted_domains"]:
        if blacklisted in domain:
            with QUALITY_STATS["blacklisted_emails"].get_lock():
                QUALITY_STATS["blacklisted_emails"].value += 1
            email_validation_cache[email] = False
            return False
    
    # Validation avec email_validator (plus stricte)
    try:
        email_validator.validate_email(email)
        email_validation_cache[email] = True
        return True
    except:
        # Validation plus permissive si email_validator échoue
        if '@' in email and '.' in email.split('@')[-1]:
            email_validation_cache[email] = True
            return True
        
        with QUALITY_STATS["invalid_emails"].get_lock():
            QUALITY_STATS["invalid_emails"].value += 1
        email_validation_cache[email] = False
        return False

@lru_cache(maxsize=10000)
def clean_username(username):
    """Nettoie et normalise un nom d'utilisateur"""
    if not username:
        return ""
    
    # Nettoyage de base
    username = username.strip()
    username = re.sub(r'^["\']|["\']$', '', username)
    
    # Traitement des cas spéciaux
    if '|' in username:
        parts = username.split('|')
        username = parts[0].strip()
    
    # Suppression des caractères non valides
    cleaned = re.sub(r'[^\w.\-@+]', '', username)
    
    # Enregistrement des statistiques
    if cleaned != username:
        with QUALITY_STATS["cleaned_usernames"].get_lock():
            QUALITY_STATS["cleaned_usernames"].value += 1
    
    return cleaned

@lru_cache(maxsize=10000)
def validate_username(username):
    if username in username_validation_cache:
        return username_validation_cache[username]
    if not username:
        with QUALITY_STATS["invalid_usernames"].get_lock():
            QUALITY_STATS["invalid_usernames"].value += 1
        username_validation_cache[username] = False
        return False
    if len(username) < CONFIG["user"]["min_length"] or len(username) > CONFIG["user"]["max_length"]:
        with QUALITY_STATS["invalid_usernames"].get_lock():
            QUALITY_STATS["invalid_usernames"].value += 1
        username_validation_cache[username] = False
        return False
    if '|' in username:
        with QUALITY_STATS["invalid_usernames"].get_lock():
            QUALITY_STATS["invalid_usernames"].value += 1
        username_validation_cache[username] = False
        return False
    username_lower = username.lower()
    for blacklisted in CONFIG["user"]["blacklisted_names"]:
        if username_lower == blacklisted:
            with QUALITY_STATS["blacklisted_usernames"].get_lock():
                QUALITY_STATS["blacklisted_usernames"].value += 1
            username_validation_cache[username] = False
            return False
    username_validation_cache[username] = True
    return True

@lru_cache(maxsize=10000)
def clean_password(password):
    if not password:
        return ""
    password = password.strip()
    password = re.sub(r'^["\']|["\']$', '', password)
    
    if password.startswith('$SHA$'):
        with QUALITY_STATS["sha_passwords_found"].get_lock():
            QUALITY_STATS["sha_passwords_found"].value += 1
    
    return password

@lru_cache(maxsize=10000)
def validate_password(password):
    if password in password_validation_cache:
        return password_validation_cache[password]
    if not password:
        with QUALITY_STATS["invalid_passwords"].get_lock():
            QUALITY_STATS["invalid_passwords"].value += 1
        password_validation_cache[password] = False
        return False
    
    # Les hashes SHA sont toujours valides
    if password.startswith('$SHA$'):
        password_validation_cache[password] = True
        return True
        
    if len(password) < CONFIG["password"]["min_length"] or len(password) > CONFIG["password"]["max_length"]:
        with QUALITY_STATS["invalid_passwords"].get_lock():
            QUALITY_STATS["invalid_passwords"].value += 1
        password_validation_cache[password] = False
        return False
    password_validation_cache[password] = True
    return True

@lru_cache(maxsize=10000)
def clean_uuid(uuid_str):
    if not uuid_str:
        return ""
    uuid_str = uuid_str.strip().lower()
    uuid_str = re.sub(r'^["\']|["\']$', '', uuid_str)
    
    if UUID_REGEX.match(uuid_str):
        return uuid_str
    else:
        try:
            uuid_obj = uuid_lib.UUID(uuid_str)
            return str(uuid_obj)
        except:
            return uuid_str
    
    return uuid_str

@lru_cache(maxsize=10000)
def validate_uuid(uuid_str):
    if uuid_str in uuid_validation_cache:
        return uuid_validation_cache[uuid_str]
    if not uuid_str:
        uuid_validation_cache[uuid_str] = True
        return True
    if not CONFIG["uuid"]["validate_format"]:
        uuid_validation_cache[uuid_str] = True
        return True
    
    if not UUID_REGEX.match(uuid_str):
        with QUALITY_STATS["invalid_uuids"].get_lock():
            QUALITY_STATS["invalid_uuids"].value += 1
        uuid_validation_cache[uuid_str] = False
        return False
        
    try:
        uuid_obj = uuid_lib.UUID(uuid_str)
        result = str(uuid_obj) == uuid_str
        uuid_validation_cache[uuid_str] = result
        return result
    except:
        with QUALITY_STATS["invalid_uuids"].get_lock():
            QUALITY_STATS["invalid_uuids"].value += 1
        uuid_validation_cache[uuid_str] = False
        return False

@lru_cache(maxsize=10000)
def clean_ip(ip):
    if not ip:
        return ""
    ip = ip.strip()
    ip = re.sub(r'^["\']|["\']$', '', ip)
    cleaned = re.sub(r'[^\d.]', '', ip)
    if cleaned != ip:
        with QUALITY_STATS["normalized_ips"].get_lock():
            QUALITY_STATS["normalized_ips"].value += 1
    return cleaned

@lru_cache(maxsize=10000)
def validate_ip(ip):
    if ip in ip_validation_cache:
        return ip_validation_cache[ip]
    if not ip:
        ip_validation_cache[ip] = True
        return True
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        with QUALITY_STATS["invalid_ips"].get_lock():
            QUALITY_STATS["invalid_ips"].value += 1
        ip_validation_cache[ip] = False
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
        if CONFIG["ip"]["exclude_private"] and ip_obj.is_private:
            with QUALITY_STATS["invalid_ips"].get_lock():
                QUALITY_STATS["invalid_ips"].value += 1
            ip_validation_cache[ip] = False
            return False
        if CONFIG["ip"]["exclude_loopback"] and ip_obj.is_loopback:
            with QUALITY_STATS["invalid_ips"].get_lock():
                QUALITY_STATS["invalid_ips"].value += 1
            ip_validation_cache[ip] = False
            return False
        if CONFIG["ip"]["exclude_link_local"] and ip_obj.is_link_local:
            with QUALITY_STATS["invalid_ips"].get_lock():
                QUALITY_STATS["invalid_ips"].value += 1
            ip_validation_cache[ip] = False
            return False
        ip_validation_cache[ip] = True
        return True
    except:
        with QUALITY_STATS["invalid_ips"].get_lock():
            QUALITY_STATS["invalid_ips"].value += 1
        ip_validation_cache[ip] = False
        return False

def clean_and_validate_record(record):
    cleaned_record = {}
    email = record.get("email", "")
    if email:
        cleaned_email = clean_email(email)
        if validate_email(cleaned_email):
            cleaned_record["email"] = cleaned_email
        else:
            cleaned_record["email"] = ""
    else:
        cleaned_record["email"] = ""
    user = record.get("user", "")
    if user:
        cleaned_user = clean_username(user)
        if validate_username(cleaned_user):
            cleaned_record["user"] = cleaned_user
        else:
            cleaned_record["user"] = ""
    else:
        cleaned_record["user"] = ""
    password = record.get("password", "")
    if password:
        cleaned_password = clean_password(password)
        if validate_password(cleaned_password):
            cleaned_record["password"] = cleaned_password
        else:
            cleaned_record["password"] = ""
    else:
        cleaned_record["password"] = ""
    uuid = record.get("uuid", "")
    if uuid:
        cleaned_uuid = clean_uuid(uuid)
        if validate_uuid(cleaned_uuid):
            cleaned_record["uuid"] = cleaned_uuid
        else:
            cleaned_record["uuid"] = ""
    else:
        cleaned_record["uuid"] = ""
    ip = record.get("ip", "")
    if ip:
        cleaned_ip = clean_ip(ip)
        if validate_ip(cleaned_ip):
            cleaned_record["ip"] = cleaned_ip
        else:
            cleaned_record["ip"] = ""
    else:
        cleaned_record["ip"] = ""
    if cleaned_record["email"] and '@' in cleaned_record["email"]:
        cleaned_record["email_domain"] = cleaned_record["email"].split('@')[-1]
    else:
        cleaned_record["email_domain"] = ""
    return cleaned_record

def is_record_valid(record):
    if not record.get("email"):
        return False
    filled_fields = sum(1 for value in record.values() if value)
    if filled_fields < CONFIG["quality_thresholds"]["min_fields_filled"]:
        return False
    return True

import subprocess
try:
    subprocess.check_call(['python', 'setup.py', 'build_ext', '--inplace'])
    logger.info("Module Cython compilé avec succès")
    if '.' not in sys.path:
        sys.path.append('.')
    module_path = None
    for ext in ['.pyd', '.so']:
        if os.path.exists(f'data_processor{ext}'):
            module_path = f'data_processor{ext}'
            break
    if module_path:
          spec = importlib.util.spec_from_file_location("data_processor", module_path)
          data_processor_module = importlib.util.module_from_spec(spec)
          spec.loader.exec_module(data_processor_module)
          DataProcessor = data_processor_module.DataProcessor
          logger.info(f"Module data_processor chargé depuis {module_path}")
    else:
        if os.path.exists('data_processor.cp311-win_amd64.pyd'):
            module_path = 'data_processor.cp311-win_amd64.pyd'
            spec = importlib.util.spec_from_file_location("data_processor", module_path)
            data_processor_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(data_processor_module)
            DataProcessor = data_processor_module.DataProcessor
            logger.info(f"Module data_processor chargé depuis {module_path}")
        else:
            raise ImportError("Module data_processor non trouvé")
except Exception as e:
    logger.error(f"Erreur lors de la compilation ou de l'importation du module Cython: {e}")
    logger.warning("Utilisation de la version Python pure comme fallback")
    class DataProcessor:
        def __init__(self, config=None, quality_stats=None):
            self.merged_data = {}
            self.processed_keys = set()
            self.email_index = {}
            self.config = config or CONFIG
            if quality_stats:
                self.quality_stats = {
                    "total_processed": 0,
                    "valid_records": 0,
                    "rejected_records": 0,
                    "duplicates_removed": 0,
                    "invalid_emails": 0,
                    "blacklisted_emails": 0,
                    "invalid_usernames": 0,
                    "blacklisted_usernames": 0,
                    "invalid_passwords": 0,
                    "invalid_ips": 0,
                    "invalid_uuids": 0,
                    "cleaned_emails": 0,
                    "cleaned_usernames": 0,
                    "normalized_ips": 0,
                    "files_processed": 0,
                    "files_with_errors": 0,
                    "records_by_source": defaultdict(int),
                }
            else:
                self.quality_stats = None
                
        def merge_record(self, record, source_file=""):
            if hasattr(self, 'quality_stats') and self.quality_stats is not None:
                self.quality_stats["total_processed"] += 1
                self.quality_stats["records_by_source"][source_file] += 1
                
            if 'clean_and_validate_record' in globals():
                record = clean_and_validate_record(record)
                
            if 'is_record_valid' in globals() and not is_record_valid(record):
                if hasattr(self, 'quality_stats') and self.quality_stats is not None:
                    self.quality_stats["rejected_records"] += 1
                return False
                
            email = record.get("email", "").lower()
            if not email or not EMAIL_REGEX.match(email) or not TLD_REGEX.search(email):
                return False
                
            user = record.get("user", "")
            if "|" in user:
                users = user.split("|")
                for single_user in users:
                    if single_user.strip():
                        self._add_user_record(single_user.strip(), email, record)
            else:
                self._add_user_record(user, email, record)
            return True
        def _add_user_record(self, user, email, record):
            user_key = f"{user.lower()}:{email.lower()}"
            if user_key not in self.processed_users:
                self.processed_users.add(user_key)
                self.merged_data[user_key] = {
                    "user": user,
                    "email": email,
                    "password": record.get("password", ""),
                    "uuid": record.get("uuid", ""),
                    "ip": record.get("ip", "")
                }
        def extract_from_txt_line(self, line):
            result = {"user": "", "email": "", "password": "", "uuid": "", "ip": ""}
            line = line.strip()
            if not line:
                return None
            match = re.search(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', line)
            if match:
                result["email"] = match.group(0)
            else:
                return None
            match = re.search(r'(?:password[:=]?\s*|pwd[:=]?\s*|pass[:=]?\s*|mdp[:=]?\s*)([\w!@#$%^&*()-_+=]{3,30})', line, re.IGNORECASE)
            if match:
                result["password"] = match.group(1)
            match = re.search(r'(?:username[:=]?\s*|user[:=]?\s*|login[:=]?\s*|pseudo[:=]?\s*)([\w.-]{2,20})', line, re.IGNORECASE)
            if match:
                result["user"] = match.group(1)
            match = re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', line, re.IGNORECASE)
            if match:
                result["uuid"] = match.group(0)
            match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            if match:
                result["ip"] = match.group(0)
            return result

def extract_from_json(file_path):
    data = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            json_data = json.load(file)
            if isinstance(json_data, list):
                for item in json_data:
                    if isinstance(item, dict):
                        record = {
                            "user": item.get("user", item.get("username", item.get("login", ""))),
                            "email": item.get("email", ""),
                            "password": item.get("password", item.get("pass", item.get("pwd", ""))),
                            "uuid": item.get("uuid", item.get("id", "")),
                            "ip": item.get("ip", item.get("ip_address", ""))
                        }
                        if record["email"]:
                            data.append(record)
            elif isinstance(json_data, dict):
                for key, value in json_data.items():
                    if isinstance(value, dict):
                        record = {
                            "user": value.get("user", value.get("username", value.get("login", ""))),
                            "email": value.get("email", ""),
                            "password": value.get("password", value.get("pass", value.get("pwd", ""))),
                            "uuid": value.get("uuid", value.get("id", "")),
                            "ip": value.get("ip", value.get("ip_address", ""))
                        }
                        if record["email"]:
                            data.append(record)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                record = {
                                    "user": item.get("user", item.get("username", item.get("login", ""))),
                                    "email": item.get("email", ""),
                                    "password": item.get("password", item.get("pass", item.get("pwd", ""))),
                                    "uuid": item.get("uuid", item.get("id", "")),
                                    "ip": item.get("ip", item.get("ip_address", ""))
                                }
                                if record["email"]:
                                    data.append(record)
    except Exception as e:
        logger.error(f"Erreur lors de l'extraction du fichier JSON {file_path}: {e}")
    
    return data

def extract_from_csv(file_path):
    data = []
    try:
        encodings = ['utf-8', 'latin1', 'cp1252', 'iso-8859-1']
        for encoding in encodings:
            try:
                try:
                    for delimiter in [',', ';', '\t', '|']:
                        try:
                            df = pd.read_csv(file_path, sep=delimiter, encoding=encoding, 
                                            on_bad_lines='skip', low_memory=True)
                            break
                        except:
                            continue
                    
                    email_cols = [col for col in df.columns if 'email' in str(col).lower()]
                    user_cols = [col for col in df.columns if any(x in str(col).lower() for x in ['user', 'username', 'login', 'pseudo'])]
                    pass_cols = [col for col in df.columns if any(x in str(col).lower() for x in ['pass', 'pwd', 'password', 'mdp'])]
                    uuid_cols = [col for col in df.columns if any(x in str(col).lower() for x in ['uuid', 'id'])]
                    ip_cols = [col for col in df.columns if any(x in str(col).lower() for x in ['ip', 'ip_address'])]
                    
                    for _, row in df.iterrows():
                        record = {"user": "", "email": "", "password": "", "uuid": "", "ip": ""}
                        
                        # Recherche d'email dans toutes les colonnes si nécessaire
                        for col in df.columns:
                            val = str(row.get(col, ""))
                            if '@' in val and '.' in val and re.search(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', val):
                                record["email"] = val
                                break
                        
                        if not record["email"]:
                            continue
                        
                        # Recherche des autres champs
                        for col in user_cols:
                            val = str(row.get(col, ""))
                            if val and val.lower() not in ["null", "none", "nan"]:
                                record["user"] = val
                                break
                        
                        for col in pass_cols:
                            val = str(row.get(col, ""))
                            if val and val.lower() not in ["null", "none", "nan"]:
                                record["password"] = val
                                break
                        
                        for col in uuid_cols:
                            val = str(row.get(col, ""))
                            if val and val.lower() not in ["null", "none", "nan"]:
                                record["uuid"] = val
                                break
                        
                        for col in ip_cols:
                            val = str(row.get(col, ""))
                            if re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', val):
                                record["ip"] = val
                                break
                        
                        data.append(record)
                    
                except Exception as e:
                    logger.warning(f"Échec de lecture avec pandas pour {file_path}: {e}")
                    # Fallback à la méthode CSV standard
                    with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                        reader = csv.reader(f)
                        headers = next(reader, [])
                        for row in reader:
                            if not row:
                                continue
                            
                            record = {"user": "", "email": "", "password": "", "uuid": "", "ip": ""}
                            
                            # Rechercher un email dans toutes les colonnes
                            for i, val in enumerate(row):
                                if '@' in val and '.' in val and re.search(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', val):
                                    record["email"] = val
                                    break
                            
                            if not record["email"]:
                                continue
                            
                            # Rechercher les autres informations
                            for i, val in enumerate(row):
                                if i < len(headers):
                                    header = headers[i].lower()
                                    if any(x in header for x in ['user', 'username', 'login', 'pseudo']):
                                        record["user"] = val
                                    elif any(x in header for x in ['pass', 'pwd', 'password', 'mdp']):
                                        record["password"] = val
                                    elif any(x in header for x in ['uuid', 'id']):
                                        record["uuid"] = val
                                    elif any(x in header for x in ['ip', 'ip_address']):
                                        record["ip"] = val
                            
                            data.append(record)
                
                break  # Si on arrive ici sans exception, on sort de la boucle des encodages
            except UnicodeDecodeError:
                continue
            except Exception as e:
                logger.error(f"Erreur avec l'encodage {encoding} pour {file_path}: {e}")
                if encoding == encodings[-1]:
                    raise e
    except Exception as e:
        logger.error(f"Erreur lors de l'extraction du fichier CSV {file_path}: {e}")
        # Fallback en mode texte
        processor = DataProcessor()
        try:
            for encoding in ['utf-8', 'latin1', 'cp1252', 'iso-8859-1']:
                try:
                    with open(file_path, 'r', encoding=encoding, errors='ignore') as file:
                        for line in file:
                            record = processor.extract_from_txt_line(line)
                            if record:
                                data.append(record)
                    break
                except UnicodeDecodeError:
                    continue
                except Exception as e2:
                    logger.error(f"Échec du fallback pour {file_path} avec l'encodage {encoding}: {e2}")
        except Exception as e2:
            logger.error(f"Échec complet du fallback pour {file_path}: {e2}")
    
    return data

def extract_from_txt(file_path):
    data = []
    processor = DataProcessor()
    try:
        encodings = ['utf-8', 'latin1', 'cp1252', 'iso-8859-1']
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding, errors='ignore') as file:
                    for line in file:
                        record = processor.extract_from_txt_line(line)
                        if record:
                            data.append(record)
                break
            except UnicodeDecodeError:
                continue
            except Exception as e:
                logger.error(f"Erreur lors de l'extraction du fichier texte {file_path} avec l'encodage {encoding}: {e}")
                if encoding == encodings[-1]:
                    raise e
    except Exception as e:
        logger.error(f"Erreur lors de l'extraction du fichier texte {file_path}: {e}")
    return data

def extract_from_sqlite(file_path):
    data = []
    try:
        conn = sqlite3.connect(file_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        for table in tables:
            table_name = table[0]
            try:
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = [col[1] for col in cursor.fetchall()]
                email_cols = [col for col in columns if 'email' in col.lower()]
                user_cols = [col for col in columns if any(x in col.lower() for x in ['user', 'username', 'login'])]
                pass_cols = [col for col in columns if any(x in col.lower() for x in ['pass', 'pwd', 'password'])]
                uuid_cols = [col for col in columns if any(x in col.lower() for x in ['uuid', 'id'])]
                ip_cols = [col for col in columns if any(x in col.lower() for x in ['ip', 'ip_address'])]
                if not email_cols:
                    continue
                cursor.execute(f"SELECT * FROM {table_name}")
                rows = cursor.fetchall()
                for row in rows:
                    row_dict = dict(zip(columns, row))
                    email = ""
                    for col in email_cols:
                        val = str(row_dict.get(col, ""))
                        if '@' in val and '.' in val:
                            email = val
                            break
                    if not email:
                        continue
                    user = ""
                    for col in user_cols:
                        val = str(row_dict.get(col, ""))
                        if val and val.lower() not in ["null", "none"]:
                            user = val
                            break
                    password = ""
                    for col in pass_cols:
                        val = str(row_dict.get(col, ""))
                        if val and val.lower() not in ["null", "none"]:
                            password = val
                            break
                    uuid = ""
                    for col in uuid_cols:
                        val = str(row_dict.get(col, ""))
                        if val and val.lower() not in ["null", "none"]:
                            uuid = val
                            break
                    ip = ""
                    for col in ip_cols:
                        val = str(row_dict.get(col, ""))
                        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', val):
                            ip = val
                            break
                    data.append({
                        "user": user,
                        "email": email,
                        "password": password,
                        "uuid": uuid,
                        "ip": ip
                    })
            except Exception as e:
                logger.error(f"Erreur lors de l'extraction de la table {table_name} dans {file_path}: {e}")
                continue
        conn.close()
    except Exception as e:
        logger.error(f"Erreur lors de l'extraction du fichier SQLite {file_path}: {e}")
    return data

def extract_from_sql(file_path):
    data = []
    processor = DataProcessor()
    try:
        encodings = ['utf-8', 'latin1', 'cp1252', 'iso-8859-1']
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding, errors='ignore') as file:
                    content = file.read()
                break
            except UnicodeDecodeError:
                continue
            except Exception as e:
                logger.error(f"Erreur lors de la lecture du fichier SQL {file_path} avec l'encodage {encoding}: {e}")
                if encoding == encodings[-1]:
                    raise e
        insert_pattern = r"INSERT\s+INTO\s+[`'\"]?(\w+)[`'\"]?\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)"
        inserts = re.finditer(insert_pattern, content, re.IGNORECASE)
        for insert in inserts:
            table = insert.group(1)
            columns = [col.strip().strip('`\'"') for col in insert.group(2).split(',')]
            values_str = insert.group(3)
            values = []
            in_string = False
            current_value = ""
            string_delimiter = None
            for char in values_str:
                if char in ["'", '"'] and (not string_delimiter or char == string_delimiter):
                    in_string = not in_string
                    if in_string:
                        string_delimiter = char
                    else:
                        string_delimiter = None
                    current_value += char
                elif char == ',' and not in_string:
                    values.append(current_value.strip())
                    current_value = ""
                else:
                    current_value += char
            if current_value:
                values.append(current_value.strip())
            row_dict = dict(zip(columns, values))
            email = ""
            for col, val in row_dict.items():
                if 'email' in col.lower() and '@' in val:
                    email = val.strip("'\"")
                    break
            if not email:
                for val in values:
                    if '@' in val and '.' in val:
                        email = val.strip("'\"")
                        break
            if not email:
                continue
            user = ""
            for col, val in row_dict.items():
                if any(x in col.lower() for x in ['user', 'username', 'login']):
                    user = val.strip("'\"")
                    break
            password = ""
            for col, val in row_dict.items():
                if any(x in col.lower() for x in ['pass', 'pwd', 'password']):
                    password = val.strip("'\"")
                    break
            uuid = ""
            for col, val in row_dict.items():
                if any(x in col.lower() for x in ['uuid', 'id']):
                    uuid = val.strip("'\"")
                    break
            ip = ""
            for col, val in row_dict.items():
                if any(x in col.lower() for x in ['ip', 'ip_address']):
                    val = val.strip("'\"")
                    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', val):
                        ip = val
                        break
            data.append({
                "user": user,
                "email": email,
                "password": password,
                "uuid": uuid,
                "ip": ip
            })
        if not data:
            for line in content.split('\n'):
                record = processor.extract_from_txt_line(line)
                if record:
                    data.append(record)
    except Exception as e:
        logger.error(f"Erreur lors de l'extraction du fichier SQL {file_path}: {e}")
    return data

def process_file(file_path):
    try:
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        logger.info(f"Traitement du fichier: {file_path}")
        if ext == '.json':
            return extract_from_json(file_path)
        elif ext == '.csv':
            return extract_from_csv(file_path)
        elif ext == '.db':
            return extract_from_sqlite(file_path)
        elif ext == '.sql':
            return extract_from_sql(file_path)
        elif ext == '.txt' or ext == '':
            return extract_from_txt(file_path)
        else:
            return extract_from_txt(file_path)
    except Exception as e:
        logger.error(f"Erreur lors du traitement du fichier {file_path}: {e}")
        return []

def main():
    start_time = time.time()
    processor = DataProcessor()
    db_folder = 'DB'
    if not os.path.exists(db_folder):
        logger.error(f"Le dossier {db_folder} n'existe pas")
        return
    file_patterns = ['*.json', '*.csv', '*.db', '*.sql', '*.txt']
    all_files = []
    for pattern in file_patterns:
        abs_path = os.path.join(os.path.abspath(db_folder), pattern)
        found_files = glob.glob(abs_path)
        logger.info(f"Pattern {pattern}: trouvé {len(found_files)} fichiers")
        all_files.extend(found_files)
    
    all_files = sorted(list(set(all_files)), key=lambda x: os.path.basename(x).lower())
    logger.info(f"Nombre total de fichiers à traiter: {len(all_files)}")
     
    max_workers = min(os.cpu_count(), 4)
    logger.info(f"Utilisation de {max_workers} workers pour le traitement parallèle")
    
    output_file = 'database.csv'
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['user', 'email', 'password', 'uuid', 'ip']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
     
    processed_files = set()
    total_records = 0
     
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {executor.submit(process_file, file): file for file in all_files}
        for future in concurrent.futures.as_completed(future_to_file):
            file = future_to_file[future]
            if file in processed_files:
                logger.warning(f"Fichier {file} déjà traité, ignoré")
                continue
            processed_files.add(file)
             
            try:
                data = future.result()
                logger.info(f"Fichier {file} traité: {len(data)} enregistrements extraits")
                
                with open(output_file, 'a', newline='', encoding='utf-8') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    for record in data:
                        if processor.merge_record(record):
                            writer.writerow({
                                'user': record.get('user', ''),
                                'email': record.get('email', ''),
                                'password': record.get('password', ''),
                                'uuid': record.get('uuid', ''),
                                'ip': record.get('ip', '')
                            })
                            total_records += 1
                            
            except Exception as e:
                logger.error(f"Erreur lors du traitement du fichier {file}: {e}")
     
    logger.info(f"Tous les fichiers ont été traités ({len(processed_files)}/{len(all_files)})")
    end_time = time.time()
    logger.info(f"Traitement terminé. {total_records} enregistrements uniques sauvegardés dans {output_file}")
    logger.info(f"Temps d'exécution total: {end_time - start_time:.2f} secondes")

if __name__ == "__main__":
    main()
