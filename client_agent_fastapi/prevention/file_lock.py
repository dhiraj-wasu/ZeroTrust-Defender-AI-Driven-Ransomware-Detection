import os
import stat
import threading
from typing import List, Set, Dict, Any
from pathlib import Path

class FileLockManager:
    """File locking and protection management"""
    
    def __init__(self):
        self.locked_files: Set[str] = set()
        self.lock = threading.Lock()
        self.backup_attributes: Dict[str, Dict[str, Any]] = {}
        
    def lock_critical_files(self, directory: str) -> List[str]:
        """Lock critical files in directory to prevent modification"""
        locked_files = []
        
        try:
            print(f"🔒 Locking critical files in: {directory}")
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Only lock important file types
                    if self._is_critical_file(file_path):
                        if self._lock_file(file_path):
                            locked_files.append(file_path)
                            with self.lock:
                                self.locked_files.add(file_path)
            
            print(f"✅ Locked {len(locked_files)} critical files")
            return locked_files
            
        except Exception as e:
            print(f"❌ File locking failed: {e}")
            return []

    def unlock_files(self, directory: str = None) -> List[str]:
        """Unlock previously locked files"""
        unlocked_files = []
        
        try:
            files_to_unlock = list(self.locked_files)
            if directory:
                files_to_unlock = [f for f in files_to_unlock if f.startswith(directory)]
            
            for file_path in files_to_unlock:
                if self._unlock_file(file_path):
                    unlocked_files.append(file_path)
                    with self.lock:
                        self.locked_files.remove(file_path)
            
            print(f"🔓 Unlocked {len(unlocked_files)} files")
            return unlocked_files
            
        except Exception as e:
            print(f"❌ File unlocking failed: {e}")
            return []

    def _is_critical_file(self, file_path: str) -> bool:
        """Check if file is critical and should be locked"""
        critical_extensions = [
            '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx',
            '.txt', '.csv', '.json', '.xml', '.sql', '.db', '.mdb',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff',
            '.mp4', '.avi', '.mov', '.wmv', '.mp3', '.wav',
            '.zip', '.rar', '.7z', '.tar', '.gz'
        ]
        
        file_ext = os.path.splitext(file_path)[1].lower()
        return file_ext in critical_extensions

    def _lock_file(self, file_path: str) -> bool:
        """Make file read-only and store original attributes"""
        try:
            if not os.path.exists(file_path):
                return False
            
            # Store original file attributes
            original_stat = os.stat(file_path)
            self.backup_attributes[file_path] = {
                'mode': original_stat.st_mode,
                'readonly': not os.access(file_path, os.W_OK)
            }
            
            # Make file read-only
            if os.name == 'nt':  # Windows
                import win32api
                import win32con
                win32api.SetFileAttributes(file_path, win32con.FILE_ATTRIBUTE_READONLY)
            else:  # Linux/Mac
                os.chmod(file_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            
            print(f"    🔒 Locked: {os.path.basename(file_path)}")
            return True
            
        except Exception as e:
            print(f"    ⚠️ Failed to lock {file_path}: {e}")
            return False

    def _unlock_file(self, file_path: str) -> bool:
        """Restore file to original writable state"""
        try:
            if not os.path.exists(file_path):
                return False
            
            # Restore original attributes if we have them
            if file_path in self.backup_attributes:
                original_attrs = self.backup_attributes[file_path]
                
                if os.name == 'nt':  # Windows
                    import win32api
                    import win32con
                    if not original_attrs['readonly']:
                        win32api.SetFileAttributes(file_path, win32con.FILE_ATTRIBUTE_NORMAL)
                else:  # Linux/Mac
                    os.chmod(file_path, original_attrs['mode'])
                
                del self.backup_attributes[file_path]
            else:
                # Default to making writable
                if os.name == 'nt':  # Windows
                    import win32api
                    import win32con
                    win32api.SetFileAttributes(file_path, win32con.FILE_ATTRIBUTE_NORMAL)
                else:  # Linux/Mac
                    os.chmod(file_path, stat.S_IWUSR | stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            
            print(f"    🔓 Unlocked: {os.path.basename(file_path)}")
            return True
            
        except Exception as e:
            print(f"    ⚠️ Failed to unlock {file_path}: {e}")
            return False

    def get_locked_files_count(self) -> int:
        """Get count of currently locked files"""
        with self.lock:
            return len(self.locked_files)

    def is_file_locked(self, file_path: str) -> bool:
        """Check if file is currently locked"""
        with self.lock:
            return file_path in self.locked_files

    def emergency_unlock_all(self) -> int:
        """Emergency unlock all files (use with caution)"""
        unlocked_count = 0
        with self.lock:
            files_to_unlock = list(self.locked_files)
            for file_path in files_to_unlock:
                if self._unlock_file(file_path):
                    self.locked_files.remove(file_path)
                    unlocked_count += 1
        
        print(f"🚨 Emergency unlocked {unlocked_count} files")
        return unlocked_count