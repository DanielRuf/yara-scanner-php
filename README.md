# yara-scanner-php
PHP-based malware scanner (depends on yara)

You can compile a prebuilt binary of yara (for Linux) with the following GitHub Actions code:

```yaml
name: CI

on:
  workflow_dispatch:
  push:
    tags:
      - '*'

jobs:
  yara:
    runs-on: ubuntu-18.04
    steps:
      - name: Compile yara (Ubuntu 18)
        run: |
          sudo apt-get install -y automake libtool make gcc pkg-config
          sudo apt-get install -y software-properties-common
          wget https://github.com/VirusTotal/yara/archive/v4.1.3.tar.gz
          tar -zxf v4.1.3.tar.gz
          cd yara-4.1.3
          ./bootstrap.sh
          ./configure --without-crypto --disable-shared
          make clean
          make
      - name: Release (v0.1.14)
        uses: softprops/action-gh-release@1e07f4398721186383de40550babbdf2b84acfc5
        if: startsWith(github.ref, 'refs/tags/')
        with:
          files: |
            yara-4.1.3/yara
            yara-4.1.3/yarac
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```
