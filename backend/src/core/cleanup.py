"""
Cleanup script to reorganize the SIEM backend structure.
"""
import os
import shutil
from pathlib import Path

# Define the root directory
ROOT_DIR = Path(__file__).parent.parent.parent

# Define the new structure
NEW_STRUCTURE = {
    'src': {
        'api': ['__init__.py', 'main.py', 'routes'],
        'core': ['__init__.py', 'config.py', 'exceptions.py', 'database.py'],
        'models': ['__init__.py', 'event.py', 'user.py', 'alert.py'],
        'services': ['__init__.py', 'threat_intelligence.py', 'log_collector.py', 'auth.py'],
        'utils': ['__init__.py', 'dashboard.py', 'settings.py', 'validators.py']
    },
    'config': ['base.yml'],
    'tests': ['__init__.py'],
    'logs': [],
    'migrations': ['__init__.py'],
}

# Directories to remove
DIRS_TO_REMOVE = [
    'analysis',
    'analytics',
    'analyzer',
    'collectors',
    'compliance',
    'defender',
    'defense',
    'deployment',
    'hunter',
    'integration',
    'intelligence',
    'monitor',
    'offensive',
    'repositories',
    'response',
    'security',
    'server',
]

def create_directory_structure(base_path: Path, structure: dict):
    """Create the new directory structure"""
    for name, content in structure.items():
        dir_path = base_path / name
        dir_path.mkdir(exist_ok=True)
        
        if isinstance(content, list):
            # Create empty files
            for file_name in content:
                file_path = dir_path / file_name
                if not file_path.exists():
                    file_path.touch()
        else:
            create_directory_structure(dir_path, content)

def remove_unnecessary_dirs():
    """Remove unnecessary directories"""
    src_dir = ROOT_DIR / 'src'
    for dir_name in DIRS_TO_REMOVE:
        dir_path = src_dir / dir_name
        if dir_path.exists():
            shutil.rmtree(dir_path)

def cleanup_project():
    """Main cleanup function"""
    try:
        # Create new structure
        create_directory_structure(ROOT_DIR, NEW_STRUCTURE)
        
        # Remove unnecessary directories
        remove_unnecessary_dirs()
        
        # Remove unnecessary files
        unnecessary_files = [
            'siem_errors.log',
            'run_tests.py',
        ]
        
        for file_name in unnecessary_files:
            file_path = ROOT_DIR / file_name
            if file_path.exists():
                os.remove(file_path)
        
        # Clean up requirements directory
        req_dir = ROOT_DIR / 'requirements'
        if req_dir.exists():
            shutil.rmtree(req_dir)
        
        print("Project structure cleaned up successfully!")
        
    except Exception as e:
        print(f"Error during cleanup: {str(e)}")

if __name__ == '__main__':
    cleanup_project()
