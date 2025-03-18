# DataSieve Pro

**DataSieve Pro** is a high-performance, advanced data cleaning, normalization, and deduplication tool designed to process massive datasets efficiently and securely.

Leveraging multi-threading, multiprocessing, and Cython optimization, this tool extracts, sanitizes, validates, and merges user-related information (emails, usernames, passwords, IPs, UUIDs) from various database formats (JSON, CSV, SQL, SQLite, TXT), providing a unified and clean output while ensuring unmatched speed and accuracy.

---

## 🚀 Features

- **Multi-format Support**: Parses and processes:
  - `.json`
  - `.csv`
  - `.db` (SQLite)
  - `.sql`
  - `.txt` & raw mixed text

- **Advanced Data Validation & Cleaning**: 
  - Emails (length validation, domain blacklist, regex validation)
  - Usernames (length check, blacklist names, character validation)
  - Passwords (hash detection: SHA, MD5, bcrypt, strong regex rules)
  - UUIDs (RFC-compliant validation)
  - IP addresses (excludes private, loopback, link-local IPs)

- **Deduplication Engine**: 
  - Detects and merges duplicate records based on email & username combinations.
  - Option to enforce max unique users.

- **Performance-Driven**:
  - **Cython Accelerated**: Core data extraction and merging functions compiled for extreme speed.
  - **Parallel Processing**: Efficient use of CPU cores (multiprocessing + multithreading).
  - **Chunk Processing**: Handles large files in manageable batches.

- **Detailed Logging & Quality Reports**:
  - Real-time logs (INFO, WARNING, ERROR levels)
  - `quality_report.log` containing detailed stats: invalid entries, duplicates, blacklisted domains, cleaned usernames, etc.
  - Timing benchmarks & file-level reports

- **Customizable Configuration**:
  - Tweak all parameters in `CONFIG`: thresholds, domain blacklists, username restrictions, performance limits, retry attempts, memory usage, etc.

- **Fallback Mechanism**: If Cython is not available, a pure Python version automatically takes over.

- **Highly Robust**: Handles unexpected formats, encoding issues, or partially broken datasets gracefully.

---

## 📂 Input Structure

Place your input database files inside a folder named `DB/` at the root of the project. Supported file types:

- `.json`
- `.csv`
- `.db` (SQLite)
- `.sql`
- `.txt`

Example:

```
DB/
├── dump1.json
├── emails.csv
├── users.db
├── backup.sql
└── mixed.txt
```

---

## 🛠️ Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/DataSieve-Pro.git
cd DataSieve-Pro
```

2. Install the dependencies:

```bash
pip install -r requirements.txt
```

3. Compile Cython modules (recommended for optimal performance):

```bash
python setup.py build_ext --inplace
```

---

## ⚙️ Usage

Run the script:

```bash
python triAI3.py
```

The tool will:

- Scan the `DB/` folder
- Extract, clean, deduplicate, and normalize all datasets
- Output results to:
  - `database.csv` (cleaned output)
  - `quality_report.log` (detailed report)

---

## 🧩 Configuration

All customization options are defined in the `CONFIG` dictionary at the top of `triAI3.py`:

```python
CONFIG = {
    "email": {
        "min_length": 5,
        "max_length": 254,
        "blacklisted_domains": ["example.com", "test.com", "temporary.com", "disposable.email"],
    },
    "user": {
        "min_length": 2,
        "max_length": 100,
        "blacklisted_names": ["admin", "test", "user", "guest", "anonymous"],
    },
    "password": {
        "min_length": 4,
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
    "performance": {
        "chunk_size": 10000,
        "max_workers": min(32, os.cpu_count() * 2),
        "memory_limit": 0.8,
        "retry_attempts": 3,
        "batch_size": 5000,
    },
    "limits": {
        "max_unique_users": 20014280,
    }
}
```

You can adjust:

- Domain blacklists
- Username blacklists
- Length thresholds
- Max memory usage
- Parallel worker count
- Duplicate limits
- Retry mechanisms

---

## 📊 Quality Metrics

After execution, consult:

- **`quality_report.log`**: 
  - Total records processed
  - Valid & rejected entries
  - Duplicate removals
  - Invalid emails/usernames/passwords/IPs/UUIDs
  - SHA hashes detected
  - Unique users count per file
  - Files with errors

Example excerpt:

```
2025-03-18 14:02:00 - Processed 250,000 records
2025-03-18 14:02:00 - Valid records: 210,000
2025-03-18 14:02:00 - Rejected records: 40,000
2025-03-18 14:02:00 - Duplicates removed: 12,000
2025-03-18 14:02:00 - Invalid emails: 8,000
2025-03-18 14:02:00 - Files processed: 40
```

---

## 🌐 Use Cases

- Data Breach Analysis & Cleaning
- Massive Credential Dumps Merging
- Security Researchers & Analysts
- ETL Pipelines needing user data validation
- Corporate data normalization across sources

---

## 💡 Why DataSieve Pro?

✅ Handles **millions of records** seamlessly  
✅ **High-speed processing** thanks to Cython & concurrency  
✅ Cleans, deduplicates & validates for **better data integrity**  
✅ Supports **messy, mixed, broken datasets** without fail  
✅ Highly **configurable & extensible** to your specific needs

---

## ✅ TODO (Future Enhancements)

- Add **Dockerfile** for easy containerized deployment
- Build **Web-based GUI Dashboard** for visual inspection
- Support for more database formats: PostgreSQL, MySQL
- Add **config.json** external configuration option
- Implement real-time **progress bar visualizations**
- Add **API wrapper** for external services integration (e.g., domain blacklists updates)

---

## 📄 License

Released under the **MIT License**.

---

## 🤝 Contributing

Contributions are welcome! If you'd like to submit a pull request, improve performance, or extend compatibility, feel free to fork the project and submit your ideas.

---

## 📬 Contact

For inquiries, issues, or collaborations:

**ByteSleuths**  
[louisduflosdu62@gmail.com]  
[https://github.com/ByteSleuths]

---

**DataSieve Pro — Clean Data, Fast Results.**

