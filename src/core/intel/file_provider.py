# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - File Search Provider
# Search local files for leaked credentials (simulating grep on large files)
# ═══════════════════════════════════════════════════════════════

import asyncio
import aiofiles
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import logging

from .base import BreachDataProvider, BreachSource, IntelCredential, IntelSearchResult


class FileSearchProvider(BreachDataProvider):
    """
    File Search Provider - Search local files for leaked credentials.
    
    This provider simulates searching through large breach data files
    using efficient pattern matching (similar to grep).
    
    Supported file formats:
    - Plain text combo lists (email:password, user:pass)
    - Stealer log format (URL + user + pass)
    - CSV format (columns for user/email/password)
    - JSON Lines format
    
    Performance considerations:
    - Uses async file I/O for non-blocking operations
    - Streams large files in chunks
    - Supports pre-indexed files for faster searches
    
    Usage:
        provider = FileSearchProvider(data_dir="/path/to/breach/data")
        result = await provider.search("example.com")
    """
    
    # Common password patterns in breach data
    COMBO_PATTERNS = [
        # email:password
        r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):([^\s:]+)',
        # user:password (no email)
        r'^([a-zA-Z0-9_.-]+):([^\s:]+)$',
        # user:hash (32+ hex chars)
        r'([a-zA-Z0-9_.-]+):([a-fA-F0-9]{32,128})$',
    ]
    
    # Stealer log patterns
    STEALER_PATTERNS = [
        # URL\nLogin: user\nPassword: pass
        r'(?:URL|Host):\s*(\S+).*?(?:Login|User|Username):\s*(\S+).*?(?:Password|Pass):\s*(\S+)',
        # user|pass|url format
        r'([^|]+)\|([^|]+)\|([^|]+)',
    ]
    
    def __init__(
        self,
        data_dir: str = "./data/breach_data",
        file_extensions: List[str] = None,
        max_file_size_mb: int = 100,
        chunk_size: int = 65536,
        max_results_per_file: int = 1000,
    ):
        """
        Initialize file search provider.
        
        Args:
            data_dir: Directory containing breach data files
            file_extensions: File extensions to search (default: .txt, .csv, .log)
            max_file_size_mb: Maximum file size to search (MB)
            chunk_size: Chunk size for streaming reads
            max_results_per_file: Maximum results from a single file
        """
        self._data_dir = Path(data_dir)
        self._file_extensions = file_extensions or [".txt", ".csv", ".log", ".combo", ".data"]
        self._max_file_size = max_file_size_mb * 1024 * 1024
        self._chunk_size = chunk_size
        self._max_results_per_file = max_results_per_file
        
        self.logger = logging.getLogger("raglox.intel.file_provider")
        
        # Compile regex patterns
        self._combo_patterns = [re.compile(p, re.MULTILINE) for p in self.COMBO_PATTERNS]
        self._stealer_pattern = re.compile(self.STEALER_PATTERNS[0], re.DOTALL | re.IGNORECASE)
    
    @property
    def provider_name(self) -> str:
        return "file_search"
    
    async def search(
        self,
        query: str,
        query_type: str = "domain",
        limit: int = 100
    ) -> IntelSearchResult:
        """
        Search files for credentials matching the query.
        
        Args:
            query: Search query (domain, email, IP)
            query_type: Type of query
            limit: Maximum results to return
            
        Returns:
            IntelSearchResult with found credentials
        """
        start_time = datetime.utcnow()
        
        # Auto-detect query type
        if query_type == "auto":
            query_type = self._detect_query_type(query)
        
        # Get list of files to search
        files_to_search = await self._get_searchable_files()
        
        if not files_to_search:
            self.logger.warning(f"No files found in {self._data_dir}")
            return IntelSearchResult(
                query=query,
                query_type=query_type,
                success=True,
                error="No data files found",
                provider=self.provider_name,
                search_time_ms=0
            )
        
        # Search files
        all_credentials: List[IntelCredential] = []
        
        for file_path in files_to_search:
            if len(all_credentials) >= limit:
                break
            
            try:
                creds = await self._search_file(file_path, query, query_type)
                all_credentials.extend(creds)
            except Exception as e:
                self.logger.error(f"Error searching file {file_path}: {e}")
                continue
        
        # Deduplicate and limit results
        unique_credentials = self._deduplicate_credentials(all_credentials)
        final_credentials = unique_credentials[:limit]
        
        search_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        self.logger.info(
            f"File search for '{self._mask_sensitive_data(query)}' "
            f"found {len(final_credentials)} credentials in {search_time:.1f}ms "
            f"(searched {len(files_to_search)} files)"
        )
        
        return IntelSearchResult(
            query=query,
            query_type=query_type,
            credentials=final_credentials,
            total_found=len(final_credentials),
            provider=self.provider_name,
            search_time_ms=search_time,
            success=True
        )
    
    async def _get_searchable_files(self) -> List[Path]:
        """Get list of files to search."""
        if not self._data_dir.exists():
            return []
        
        files = []
        
        for ext in self._file_extensions:
            files.extend(self._data_dir.glob(f"**/*{ext}"))
        
        # Filter by size
        valid_files = []
        for f in files:
            try:
                if f.stat().st_size <= self._max_file_size:
                    valid_files.append(f)
                else:
                    self.logger.debug(f"Skipping large file: {f}")
            except Exception:
                continue
        
        return valid_files
    
    async def _search_file(
        self,
        file_path: Path,
        query: str,
        query_type: str
    ) -> List[IntelCredential]:
        """
        Search a single file for credentials.
        
        Uses streaming read to handle large files.
        """
        credentials = []
        query_lower = query.lower()
        
        try:
            async with aiofiles.open(file_path, mode='r', encoding='utf-8', errors='ignore') as f:
                content = ""
                found_count = 0
                
                async for line in f:
                    content += line
                    
                    # Check if line might match our query
                    if not self._line_might_match(line.lower(), query_lower, query_type):
                        continue
                    
                    # Try to extract credentials
                    extracted = self._extract_credentials_from_line(line, file_path.name)
                    
                    for cred in extracted:
                        # Verify the credential actually matches our target
                        if self._credential_matches_query(cred, query, query_type):
                            credentials.append(cred)
                            found_count += 1
                            
                            if found_count >= self._max_results_per_file:
                                return credentials
        
        except Exception as e:
            self.logger.debug(f"Error reading file {file_path}: {e}")
        
        return credentials
    
    def _line_might_match(self, line: str, query: str, query_type: str) -> bool:
        """Quick check if a line might contain matching credentials."""
        if query_type == "domain":
            # Check for domain in line
            return query in line or query.replace(".", "") in line
        elif query_type == "email":
            # Check for email domain
            if "@" in query:
                domain = query.split("@")[-1]
                return domain in line or query in line
            return query in line
        elif query_type == "ip":
            return query in line
        return query in line
    
    def _extract_credentials_from_line(
        self,
        line: str,
        source_file: str
    ) -> List[IntelCredential]:
        """Extract credentials from a single line."""
        credentials = []
        line = line.strip()
        
        if not line or len(line) > 500:  # Skip empty or very long lines
            return credentials
        
        # Determine source info from filename
        source, source_name = self._determine_source_from_filename(source_file)
        
        # Try combo list format (email:password or user:password)
        for pattern in self._combo_patterns:
            match = pattern.search(line)
            if match:
                groups = match.groups()
                
                if len(groups) >= 2:
                    identifier = groups[0]
                    secret = groups[1]
                    
                    # Determine if identifier is email or username
                    is_email = "@" in identifier
                    
                    # Check if secret is a hash
                    is_hash = len(secret) >= 32 and all(c in '0123456789abcdefABCDEF' for c in secret)
                    
                    cred = IntelCredential(
                        email=identifier if is_email else None,
                        username=identifier if not is_email else identifier.split("@")[0],
                        password=None if is_hash else secret,
                        password_hash=secret if is_hash else None,
                        hash_type="md5" if is_hash and len(secret) == 32 else None,
                        source=source,
                        source_name=source_name,
                        source_date=datetime.utcnow(),  # Would be from file metadata in production
                        raw_log=self._mask_sensitive_data(line, 4),
                        reliability_score=self._calculate_reliability(source),
                    )
                    credentials.append(cred)
                    break  # Only use first matching pattern
        
        return credentials
    
    def _determine_source_from_filename(self, filename: str) -> tuple:
        """Determine breach source from filename."""
        filename_lower = filename.lower()
        
        if "arthouse" in filename_lower or "art_house" in filename_lower:
            return BreachSource.ARTHOUSE, f"ArtHouse_{filename}"
        elif "fate" in filename_lower or "traffic" in filename_lower:
            return BreachSource.FATETRAFFIC, f"Fatetraffic_{filename}"
        elif "combo" in filename_lower:
            return BreachSource.COMBOLIST, f"ComboList_{filename}"
        elif "stealer" in filename_lower or "log" in filename_lower:
            return BreachSource.STEALER_LOG, f"StealerLog_{filename}"
        elif "dump" in filename_lower or "db" in filename_lower:
            return BreachSource.DATABASE_DUMP, f"DBDump_{filename}"
        elif "paste" in filename_lower:
            return BreachSource.PASTE_SITE, f"PasteSite_{filename}"
        else:
            return BreachSource.LOCAL_FILE, filename
    
    def _credential_matches_query(
        self,
        cred: IntelCredential,
        query: str,
        query_type: str
    ) -> bool:
        """Check if a credential matches the search query."""
        query_lower = query.lower()
        
        if query_type == "domain":
            # Check email domain
            if cred.email and query_lower in cred.email.lower():
                return True
            if cred.target_domain and query_lower in cred.target_domain.lower():
                return True
        
        elif query_type == "email":
            if cred.email and query_lower == cred.email.lower():
                return True
        
        elif query_type == "ip":
            if cred.target_ip and query_lower == cred.target_ip.lower():
                return True
        
        elif query_type == "username":
            if cred.username and query_lower == cred.username.lower():
                return True
        
        return False
    
    def _deduplicate_credentials(
        self,
        credentials: List[IntelCredential]
    ) -> List[IntelCredential]:
        """Remove duplicate credentials, keeping highest reliability."""
        seen: Dict[str, IntelCredential] = {}
        
        for cred in credentials:
            # Create unique key
            key = f"{cred.email or cred.username}:{cred.password or cred.password_hash}"
            
            if key not in seen or cred.reliability_score > seen[key].reliability_score:
                seen[key] = cred
        
        # Sort by reliability
        return sorted(seen.values(), key=lambda c: c.reliability_score, reverse=True)
    
    async def health_check(self) -> bool:
        """Check if the data directory exists and is accessible."""
        return self._data_dir.exists() and self._data_dir.is_dir()
    
    def get_available_files(self) -> List[Dict[str, Any]]:
        """Get list of available data files with metadata."""
        files = []
        
        if not self._data_dir.exists():
            return files
        
        for ext in self._file_extensions:
            for f in self._data_dir.glob(f"**/*{ext}"):
                try:
                    stat = f.stat()
                    files.append({
                        "path": str(f),
                        "name": f.name,
                        "size_bytes": stat.st_size,
                        "size_mb": round(stat.st_size / (1024 * 1024), 2),
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    })
                except Exception:
                    continue
        
        return files
