import os
import shutil
import zipfile
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import asyncio
from pathlib import Path

class BackupManager:
    """Emergency backup management system"""
    
    def __init__(self, source_dir: str, backup_dir: str, important_folders: List[str] = None):
        self.source_dir = source_dir
        self.backup_dir = backup_dir
        self.important_folders = important_folders or []
        self.backup_metadata_file = os.path.join(backup_dir, "backup_metadata.json")
        
        # Create backup directory if it doesn't exist
        os.makedirs(self.backup_dir, exist_ok=True)
        
        # Load backup metadata
        self.backup_metadata = self._load_metadata()

    async def create_initial_backup(self) -> str:
        """Create initial comprehensive backup"""
        print("💾 Creating initial backup...")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"initial_backup_{timestamp}"
        backup_path = os.path.join(self.backup_dir, f"{backup_name}.zip")
        
        try:
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Backup important folders with priority
                for folder in self.important_folders:
                    folder_path = os.path.join(self.source_dir, folder)
                    if os.path.exists(folder_path):
                        await self._add_folder_to_zip(zipf, folder_path, folder)
                        print(f"  ✅ Backed up important folder: {folder}")
                
                # Backup all files in source directory
                file_count = 0
                for root, dirs, files in os.walk(self.source_dir):
                    # Skip important folders already backed up
                    dirs[:] = [d for d in dirs if os.path.join(root, d) not in 
                              [os.path.join(self.source_dir, f) for f in self.important_folders]]
                    
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            # Calculate relative path for zip
                            rel_path = os.path.relpath(file_path, self.source_dir)
                            zipf.write(file_path, rel_path)
                            file_count += 1
                        except Exception as e:
                            print(f"  ⚠️ Could not backup {file_path}: {e}")
                
                print(f"  📁 Total files backed up: {file_count}")
            
            # Update metadata
            self._update_metadata(backup_name, backup_path, "initial", file_count)
            
            print(f"✅ Initial backup created: {backup_path}")
            return backup_path
            
        except Exception as e:
            print(f"❌ Initial backup failed: {e}")
            return None

    async def create_emergency_backup(self) -> str:
        """Create emergency backup of critical files only"""
        print("🚨 Creating emergency backup...")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"emergency_backup_{timestamp}"
        backup_path = os.path.join(self.backup_dir, f"{backup_name}.zip")
        
        try:
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                file_count = 0
                
                # Only backup important folders in emergency
                for folder in self.important_folders:
                    folder_path = os.path.join(self.source_dir, folder)
                    if os.path.exists(folder_path):
                        folder_files = await self._add_folder_to_zip(zipf, folder_path, folder)
                        file_count += folder_files
                        print(f"  🔒 Emergency backup of: {folder} ({folder_files} files)")
                
                # Also backup any files directly in source directory with important extensions
                important_extensions = ['.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx', '.txt']
                for file in os.listdir(self.source_dir):
                    file_path = os.path.join(self.source_dir, file)
                    if os.path.isfile(file_path) and any(file.lower().endswith(ext) for ext in important_extensions):
                        try:
                            zipf.write(file_path, file)
                            file_count += 1
                        except Exception as e:
                            print(f"  ⚠️ Could not backup {file}: {e}")
            
            # Update metadata
            self._update_metadata(backup_name, backup_path, "emergency", file_count)
            
            print(f"✅ Emergency backup created: {backup_path} ({file_count} files)")
            return backup_path
            
        except Exception as e:
            print(f"❌ Emergency backup failed: {e}")
            return None

    async def create_incremental_backup(self) -> Optional[str]:
        """Create incremental backup of changed files"""
        print("🔄 Creating incremental backup...")
        
        # Get last backup time
        last_backup_time = self._get_last_backup_time()
        if not last_backup_time:
            print("  ⚠️ No previous backup found, creating full backup")
            return await self.create_initial_backup()
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"incremental_backup_{timestamp}"
        backup_path = os.path.join(self.backup_dir, f"{backup_name}.zip")
        
        try:
            changed_files = []
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Find files changed since last backup
                for root, dirs, files in os.walk(self.source_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                            if mod_time > last_backup_time:
                                rel_path = os.path.relpath(file_path, self.source_dir)
                                zipf.write(file_path, rel_path)
                                changed_files.append(rel_path)
                        except Exception:
                            continue
                
                print(f"  📁 Changed files backed up: {len(changed_files)}")
            
            if changed_files:
                self._update_metadata(backup_name, backup_path, "incremental", len(changed_files))
                print(f"✅ Incremental backup created: {backup_path}")
                return backup_path
            else:
                os.remove(backup_path)  # Remove empty backup
                print("  ℹ️ No changes since last backup")
                return None
                
        except Exception as e:
            print(f"❌ Incremental backup failed: {e}")
            return None

    async def _add_folder_to_zip(self, zipf: zipfile.ZipFile, folder_path: str, arcname: str) -> int:
        """Add folder to zip file and return file count"""
        file_count = 0
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    # Calculate relative path within the folder
                    rel_path = os.path.join(arcname, os.path.relpath(file_path, folder_path))
                    zipf.write(file_path, rel_path)
                    file_count += 1
                except Exception as e:
                    print(f"    ⚠️ Could not add {file_path}: {e}")
                    continue
        return file_count

    def _load_metadata(self) -> Dict[str, Any]:
        """Load backup metadata from file"""
        try:
            if os.path.exists(self.backup_metadata_file):
                with open(self.backup_metadata_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading backup metadata: {e}")
        return {"backups": []}

    def _update_metadata(self, backup_name: str, backup_path: str, 
                        backup_type: str, file_count: int):
        """Update backup metadata"""
        backup_info = {
            "name": backup_name,
            "path": backup_path,
            "type": backup_type,
            "file_count": file_count,
            "timestamp": datetime.now().isoformat(),
            "size": os.path.getsize(backup_path) if os.path.exists(backup_path) else 0
        }
        
        self.backup_metadata.setdefault("backups", []).append(backup_info)
        
        # Keep only last 10 backups in metadata
        if len(self.backup_metadata["backups"]) > 10:
            self.backup_metadata["backups"] = self.backup_metadata["backups"][-10:]
        
        # Remove oldest backups from disk if we have more than 10
        self._cleanup_old_backups()
        
        # Save metadata
        self._save_metadata()

    def _save_metadata(self):
        """Save backup metadata to file"""
        try:
            with open(self.backup_metadata_file, 'w') as f:
                json.dump(self.backup_metadata, f, indent=2)
        except Exception as e:
            print(f"Error saving backup metadata: {e}")

    def _get_last_backup_time(self) -> Optional[datetime]:
        """Get timestamp of last backup"""
        if not self.backup_metadata.get("backups"):
            return None
        
        last_backup = self.backup_metadata["backups"][-1]
        return datetime.fromisoformat(last_backup["timestamp"])

    def _cleanup_old_backups(self):
        """Remove old backup files beyond the limit"""
        try:
            backups = self.backup_metadata.get("backups", [])
            if len(backups) <= 10:
                return
            
            # Remove oldest backups
            backups_to_remove = backups[:-10]
            for backup in backups_to_remove:
                backup_path = backup["path"]
                if os.path.exists(backup_path):
                    os.remove(backup_path)
                    print(f"🧹 Removed old backup: {backup_path}")
            
            # Update metadata
            self.backup_metadata["backups"] = backups[-10:]
            self._save_metadata()
            
        except Exception as e:
            print(f"Error cleaning up old backups: {e}")

    async def list_backups(self) -> List[Dict[str, Any]]:
        """List all available backups"""
        return self.backup_metadata.get("backups", [])

    async def restore_backup(self, backup_name: str, target_dir: str = None) -> bool:
        """Restore files from backup"""
        target_dir = target_dir or self.source_dir
        
        # Find backup in metadata
        backup_info = None
        for backup in self.backup_metadata.get("backups", []):
            if backup["name"] == backup_name:
                backup_info = backup
                break
        
        if not backup_info:
            print(f"❌ Backup not found: {backup_name}")
            return False
        
        backup_path = backup_info["path"]
        if not os.path.exists(backup_path):
            print(f"❌ Backup file not found: {backup_path}")
            return False
        
        try:
            print(f"🔄 Restoring backup: {backup_name}")
            with zipfile.ZipFile(backup_path, 'r') as zipf:
                zipf.extractall(target_dir)
            
            print(f"✅ Backup restored successfully: {backup_name}")
            return True
            
        except Exception as e:
            print(f"❌ Backup restoration failed: {e}")
            return False

    async def get_backup_stats(self) -> Dict[str, Any]:
        """Get backup statistics"""
        backups = self.backup_metadata.get("backups", [])
        total_size = sum(backup.get("size", 0) for backup in backups)
        total_files = sum(backup.get("file_count", 0) for backup in backups)
        
        return {
            "total_backups": len(backups),
            "total_size_bytes": total_size,
            "total_files_backed_up": total_files,
            "last_backup": backups[-1]["timestamp"] if backups else None,
            "backup_types": [b["type"] for b in backups]
        }