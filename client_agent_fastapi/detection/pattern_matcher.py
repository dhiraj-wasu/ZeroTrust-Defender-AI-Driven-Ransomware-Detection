import re
import os
import hashlib
from typing import Dict, List, Any, Set, Tuple
import yara
from datetime import datetime

class PatternMatcher:
    """Advanced pattern matching for ransomware detection"""
    
    def __init__(self):
        self.ransomware_patterns = self._load_ransomware_patterns()
        self.suspicious_strings = self._load_suspicious_strings()
        self.file_signatures = self._load_file_signatures()
        self.yara_rules = None
        
        # Compile YARA rules
        self._compile_yara_rules()

    def _load_ransomware_patterns(self) -> Dict[str, Any]:
        """Load ransomware detection patterns"""
        return {
            'file_extensions': {
                'encrypted': [
                    r'\.encrypted$', r'\.locked$', r'\.crypto$', r'\.ransom$',
                    r'\.wncry$', r'\.cryptolocker$', r'\.cryptowall$',
                    r'\.cerber$', r'\.zeppelin$', r'\.locky$', r'\.petya$'
                ],
                'ransom_notes': [
                    r'readme.*\.txt$', r'decrypt.*\.txt$', r'recover.*\.txt$',
                    r'instruction.*\.txt$', r'help.*\.txt$', r'how_to_recover.*\.txt$',
                    r'ransom.*\.txt$', r'payment.*\.txt$', r'bitcoin.*\.txt$'
                ]
            },
            'process_names': [
                r'crypto.*\.exe$', r'encrypt.*\.exe$', r'ransom.*\.exe$',
                r'locker.*\.exe$', r'wannacry.*\.exe$', r'petya.*\.exe$',
                r'cerber.*\.exe$', r'locky.*\.exe$', r'cryptolocker.*\.exe$'
            ],
            'network_patterns': [
                r'tor\.exe$', r'tor\\', r'hidden_service', r'onion'
            ]
        }

    def _load_suspicious_strings(self) -> List[str]:
        """Load suspicious strings commonly found in ransomware"""
        return [
            "your files are encrypted", "pay the ransom", "bitcoin wallet",
            "decryption key", "recover your files", "payment required",
            "your data is locked", "encryption algorithm", "ransom note",
            "decryption service", "bitcoin address", "cryptocurrency",
            "locker software", "file recovery", "payment deadline"
        ]

    def _load_file_signatures(self) -> Dict[bytes, str]:
        """Load file signatures for type verification"""
        return {
            b'%PDF': 'pdf',
            b'PK\x03\x04': 'zip',
            b'Rar!\x1a\x07': 'rar',
            b'\x7fELF': 'elf',
            b'MZ': 'exe',
            b'\x89PNG': 'png',
            b'\xff\xd8\xff': 'jpg'
        }

    def _compile_yara_rules(self):
        """Compile YARA rules for advanced pattern matching"""
        try:
            rules = """
                rule RansomwareNote {
                    strings:
                        $s1 = "your files are encrypted"
                        $s2 = "pay the ransom"
                        $s3 = "bitcoin wallet"
                        $s4 = "decryption key"
                    condition:
                        any of them
                }
                
                rule SuspiciousExtension {
                    strings:
                        $ext1 = ".encrypted"
                        $ext2 = ".locked"
                        $ext3 = ".crypto"
                        $ext4 = ".ransom"
                    condition:
                        any of them
                }
                
                rule EncryptionKeywords {
                    strings:
                        $k1 = "AES"
                        $k2 = "RSA"
                        $k3 = "encrypt"
                        $k4 = "decrypt"
                        $k5 = "cipher"
                    condition:
                        3 of them
                }
            """
            self.yara_rules = yara.compile(source=rules)
        except Exception as e:
            print(f"YARA rule compilation failed: {e}")
            self.yara_rules = None

    async def analyze_file_patterns(self, file_path: str) -> Dict[str, Any]:
        """Analyze file for ransomware patterns"""
        analysis = {
            'suspicious_patterns': [],
            'confidence': 0.0,
            'threat_level': 'normal',
            'matched_rules': [],
            'file_type_verification': None
        }
        
        try:
            # Check file extension patterns
            extension_matches = self._check_extension_patterns(file_path)
            if extension_matches:
                analysis['suspicious_patterns'].extend(extension_matches)
                analysis['confidence'] += 0.3
            
            # Check file name patterns
            name_matches = self._check_filename_patterns(file_path)
            if name_matches:
                analysis['suspicious_patterns'].extend(name_matches)
                analysis['confidence'] += 0.2
            
            # Check file content patterns
            content_matches = await self._check_content_patterns(file_path)
            if content_matches:
                analysis['suspicious_patterns'].extend(content_matches)
                analysis['confidence'] += 0.4
            
            # Verify file signature
            signature_check = await self._verify_file_signature(file_path)
            analysis['file_type_verification'] = signature_check
            if signature_check.get('mismatch', False):
                analysis['confidence'] += 0.1
            
            # Apply YARA rules
            yara_matches = await self._apply_yara_rules(file_path)
            if yara_matches:
                analysis['suspicious_patterns'].extend(yara_matches)
                analysis['matched_rules'] = yara_matches
                analysis['confidence'] += len(yara_matches) * 0.1
            
            # Cap confidence at 1.0
            analysis['confidence'] = min(1.0, analysis['confidence'])
            
            # Determine threat level
            if analysis['confidence'] > 0.7:
                analysis['threat_level'] = 'critical'
            elif analysis['confidence'] > 0.5:
                analysis['threat_level'] = 'high'
            elif analysis['confidence'] > 0.3:
                analysis['threat_level'] = 'suspicious'
            
        except Exception as e:
            print(f"Pattern analysis error for {file_path}: {e}")
        
        return analysis

    def _check_extension_patterns(self, file_path: str) -> List[str]:
        """Check for suspicious file extensions"""
        matches = []
        filename = os.path.basename(file_path).lower()
        
        for pattern_type, patterns in self.ransomware_patterns['file_extensions'].items():
            for pattern in patterns:
                if re.search(pattern, filename):
                    matches.append(f"suspicious_extension_{pattern_type}")
        
        return matches

    def _check_filename_patterns(self, file_path: str) -> List[str]:
        """Check for suspicious filename patterns"""
        matches = []
        filename = os.path.basename(file_path).lower()
        
        # Check for ransom note patterns
        ransom_patterns = [
            r'readme', r'decrypt', r'recover', r'instruction',
            r'help', r'how_to', r'ransom', r'payment'
        ]
        
        for pattern in ransom_patterns:
            if re.search(pattern, filename):
                matches.append(f"ransom_note_pattern_{pattern}")
        
        # Check for encrypted file patterns
        encrypted_patterns = [
            r'encrypted', r'locked', r'crypto', r'crypted'
        ]
        
        for pattern in encrypted_patterns:
            if re.search(pattern, filename):
                matches.append(f"encrypted_file_pattern_{pattern}")
        
        return matches

    async def _check_content_patterns(self, file_path: str) -> List[str]:
        """Check file content for suspicious patterns"""
        matches = []
        
        try:
            if not os.path.exists(file_path) or os.path.isdir(file_path):
                return matches
            
            file_size = os.path.getsize(file_path)
            if file_size == 0 or file_size > 10 * 1024 * 1024:  # Skip empty or large files
                return matches
            
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1024 * 1024)  # Read first 1MB
                content_lower = content.lower()
            
            # Check for suspicious strings
            for suspicious_string in self.suspicious_strings:
                if suspicious_string in content_lower:
                    matches.append(f"suspicious_content_{suspicious_string[:20]}")
            
            # Check for encryption-related patterns
            encryption_patterns = [
                r'aes[-_\s]*(128|256)?', r'rsa[-_\s]*2048', r'encryption[-_\s]*key',
                r'decryption[-_\s]*key', r'cipher[-_\s]*text', r'crypto[-_\s]*graphic'
            ]
            
            for pattern in encryption_patterns:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    matches.append(f"encryption_pattern_{pattern}")
            
            # Check for Bitcoin addresses
            bitcoin_pattern = r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}'
            if re.search(bitcoin_pattern, content):
                matches.append("bitcoin_address_detected")
            
        except Exception as e:
            print(f"Content pattern check error for {file_path}: {e}")
        
        return matches

    async def _verify_file_signature(self, file_path: str) -> Dict[str, Any]:
        """Verify file signature matches extension"""
        try:
            if not os.path.exists(file_path):
                return {'error': 'file_not_found'}
            
            with open(file_path, 'rb') as f:
                header = f.read(8)  # Read first 8 bytes
            
            # Get file extension
            file_ext = os.path.splitext(file_path)[1].lower().lstrip('.')
            
            # Check against known signatures
            for signature, expected_type in self.file_signatures.items():
                if header.startswith(signature):
                    return {
                        'detected_type': expected_type,
                        'expected_type': file_ext,
                        'mismatch': expected_type != file_ext,
                        'confidence': 'high'
                    }
            
            return {
                'detected_type': 'unknown',
                'expected_type': file_ext,
                'mismatch': False,
                'confidence': 'low'
            }
            
        except Exception as e:
            return {'error': str(e)}

    async def _apply_yara_rules(self, file_path: str) -> List[str]:
        """Apply YARA rules to file"""
        if not self.yara_rules:
            return []
        
        try:
            matches = self.yara_rules.match(file_path)
            return [str(match) for match in matches]
        except Exception as e:
            print(f"YARA rule matching error for {file_path}: {e}")
            return []

    async def analyze_process_patterns(self, process_name: str, process_path: str) -> Dict[str, Any]:
        """Analyze process for ransomware patterns"""
        analysis = {
            'suspicious_patterns': [],
            'confidence': 0.0,
            'threat_level': 'normal'
        }
        
        process_name_lower = process_name.lower()
        process_path_lower = process_path.lower()
        
        # Check process name patterns
        for pattern in self.ransomware_patterns['process_names']:
            if re.search(pattern, process_name_lower):
                analysis['suspicious_patterns'].append(f"suspicious_process_name_{pattern}")
                analysis['confidence'] += 0.4
        
        # Check process path patterns
        for pattern in self.ransomware_patterns['network_patterns']:
            if re.search(pattern, process_path_lower):
                analysis['suspicious_patterns'].append(f"suspicious_process_path_{pattern}")
                analysis['confidence'] += 0.3
        
        # Check for system process impersonation
        system_processes = ['lsass.exe', 'services.exe', 'winlogon.exe', 'csrss.exe']
        if process_name_lower in system_processes and not process_path_lower.startswith('c:\\windows\\system32'):
            analysis['suspicious_patterns'].append('system_process_impersonation')
            analysis['confidence'] += 0.5
        
        # Cap confidence
        analysis['confidence'] = min(1.0, analysis['confidence'])
        
        # Determine threat level
        if analysis['confidence'] > 0.6:
            analysis['threat_level'] = 'critical'
        elif analysis['confidence'] > 0.4:
            analysis['threat_level'] = 'high'
        elif analysis['confidence'] > 0.2:
            analysis['threat_level'] = 'suspicious'
        
        return analysis

    async def analyze_network_patterns(self, remote_host: str, port: int, 
                                     protocol: str) -> Dict[str, Any]:
        """Analyze network patterns for ransomware activity"""
        analysis = {
            'suspicious_patterns': [],
            'confidence': 0.0,
            'threat_level': 'normal'
        }
        
        # Check for suspicious ports
        suspicious_ports = [445, 3389, 22, 23, 135, 139, 443]
        if port in suspicious_ports:
            analysis['suspicious_patterns'].append(f"suspicious_port_{port}")
            analysis['confidence'] += 0.3
        
        # Check for known C2 patterns
        c2_patterns = [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address
            r'.*\.onion$',  # Tor hidden service
            r'.*\.tk$', r'.*\.ml$', r'.*\.ga$', r'.*\.cf$'  # Free domains often used by malware
        ]
        
        for pattern in c2_patterns:
            if re.search(pattern, remote_host):
                analysis['suspicious_patterns'].append(f"c2_pattern_{pattern}")
                analysis['confidence'] += 0.2
        
        # Check for encrypted protocols on unusual ports
        if protocol == 'tcp' and port not in [443, 993, 995, 22]:
            analysis['suspicious_patterns'].append('unusual_encrypted_port')
            analysis['confidence'] += 0.1
        
        # Cap confidence
        analysis['confidence'] = min(1.0, analysis['confidence'])
        
        # Determine threat level
        if analysis['confidence'] > 0.5:
            analysis['threat_level'] = 'high'
        elif analysis['confidence'] > 0.3:
            analysis['threat_level'] = 'suspicious'
        
        return analysis

    def get_pattern_statistics(self) -> Dict[str, Any]:
        """Get pattern matching statistics"""
        return {
            'ransomware_patterns_count': len(self.ransomware_patterns['file_extensions']['encrypted']),
            'suspicious_strings_count': len(self.suspicious_strings),
            'file_signatures_count': len(self.file_signatures),
            'yara_rules_loaded': self.yara_rules is not None,
            'pattern_categories': list(self.ransomware_patterns.keys())
        }

# Global pattern matcher instance
pattern_matcher = PatternMatcher() 