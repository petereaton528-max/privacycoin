"""Bundled desktop entry point; no WSL, PATH runtime or developer installation."""
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))

def main():
    from apps.network_v1.desktop import main as desktop
    sys.argv=[sys.argv[0],'--backend-root',str(ROOT),*sys.argv[1:]]
    desktop()

if __name__=='__main__':main()
