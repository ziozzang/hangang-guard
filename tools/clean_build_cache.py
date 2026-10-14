#!/usr/bin/env python3
"""Inspect or remove only reproducible Rust incremental caches; never release assets."""
import argparse
import shutil
from pathlib import Path


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--repo',action='append',type=Path,help='Explicit Cargo repository; default is this repository')
    parser.add_argument('--apply',action='store_true',help='Remove incremental caches when no Rust build is running')
    args=parser.parse_args()
    repos=args.repo or [Path(__file__).resolve().parents[1]]
    if args.apply:
        for process in Path('/proc').glob('[0-9]*/comm'):
            try:
                if process.read_text().strip() in ['cargo','rustc']:
                    print('Skipped: a Rust build is active');return
            except OSError:pass
    for repo in repos:
        repo=repo.resolve()
        if not (repo/'Cargo.toml').is_file():raise RuntimeError('Explicit repository must contain Cargo.toml')
        cache=repo/'target/debug/incremental'
        if not cache.exists():continue
        if cache.is_symlink() or cache.resolve()!=cache:
            raise RuntimeError('Refusing a symlinked incremental cache path')
        size=sum(path.stat().st_size for path in cache.rglob('*') if path.is_file() and not path.is_symlink())
        print(f'{repo.name}: incremental cache {size / 1024**3:.2f} GiB')
        if args.apply:
            shutil.rmtree(cache);cache.mkdir();print('Removed reproducible incremental cache')
    disk=shutil.disk_usage(Path.home())
    print(f'Home filesystem free: {disk.free / 1024**3:.1f} GiB')


if __name__=='__main__':main()
