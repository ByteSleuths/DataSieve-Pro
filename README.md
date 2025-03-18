# DataSieve Pro

**DataSieve Pro** is a high-performance, advanced data cleaning, normalization, and deduplication tool designed to process massive datasets efficiently.

Leveraging multi-threading, multiprocessing, and Cython optimization, this tool extracts and sanitizes user-related information (emails, usernames, passwords, IPs, UUIDs) from various database formats (JSON, CSV, SQL, SQLite, TXT), providing a unified and clean output.

---

## 🚀 Features

- **Multi-format Support**: Parses `.json`, `.csv`, `.db` (SQLite), `.sql`, `.txt`, and mixed text files.
- **Advanced Data Validation**: Cleans and validates:
  - Emails (with domain blacklisting)
  - Usernames (blacklisted terms, length checks)
  - Passwords (hash detection: SHA, MD5, bcrypt)
  - UUIDs
  - IP addresses (excludes private, loopback, link-local IPs)
- **Deduplication Engine**: Ensures uniqueness based on email and username combinations.
- **Cython Accelerated**: Critical sections of the codebase are optimized using Cython for extreme speed.
- **Parallel Processing**: Utilizes CPU cores efficiently with multi-threading and multi-processing.
- **Detailed Logging & Quality Reports**: Provides logs and statistics on data quality (invalid entries, duplicates, cleaned entries).
- **Custom Configuration**: Adjustable thresholds, limits, and blacklists.

---

## 📂 Input Structure

Place your input database files inside a folder named `DB/` at the root of the project. Supported file types:

- `.json`
- `.csv`
- `.db` (SQLite)
- `.sql`
- `.txt`

---

## 🛠️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/DataSieve-Pro.git
   cd DataSieve-Pro
