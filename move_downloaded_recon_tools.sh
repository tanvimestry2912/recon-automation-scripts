#!/usr/bin/env bash
# move_downloaded_recon_tools.sh
# Move matching recon tools from ~/Downloads to /opt/recon_tools, set ownership, create symlinks for executables.
# Run with sudo: sudo ./move_downloaded_recon_tools.sh

set -euo pipefail
IFS=$'\n\t'

# Detect real user (when run with sudo)
REAL_USER="${SUDO_USER:-$(whoami)}"
USER_HOME="/home/${REAL_USER}"
DOWNLOADS_DIR="${USER_HOME}/Downloads"
TARGET_DIR="/opt/recon_tools"
BIN_LINK_DIR="/usr/local/bin"

mkdir -p "$TARGET_DIR"
chown root:root "$TARGET_DIR" || true

# Tools referenced in your script (pattern list)
patterns=(
  "amass"
  "subfinder"
  "findomain"
  "Sublist3r"
  "httpx"
  "katana"
  "ParamSpider"
  "paramspider"
  "ffuf"
  "dalfox"
  "XSStrike"
  "xsstrike"
  "sqlmap"
  "ghauri"
  "subzy"
  "403bypasser"
  "403-bypass"
  "katana"
  "web_reconn_tools"
  "subdomain_tools"
)

echo "[*] User detected: $REAL_USER"
echo "[*] From: $DOWNLOADS_DIR"
echo "[*] To:   $TARGET_DIR"
echo

moved=()
skipped=()
found_any=0

shopt -s nullglob
for pat in "${patterns[@]}"; do
  # look for directories or files matching the pattern (case-sensitive and insensitive)
  # check both direct name matches and wildcard matches
  matches=( "$DOWNLOADS_DIR"/"$pat" "$DOWNLOADS_DIR"/"$pat"* "$DOWNLOADS_DIR"/"${pat,,}"* "$DOWNLOADS_DIR"/"${pat^^}"* )
  for m in "${matches[@]}"; do
    if [ -e "$m" ]; then
      found_any=1
      base=$(basename "$m")
      dest="$TARGET_DIR/$base"
      if [ -e "$dest" ]; then
        echo "[!] Destination already exists, skipping move of $m -> $dest"
        skipped+=("$m")
      else
        echo "[+] Moving: $m -> $dest"
        mv -n "$m" "$TARGET_DIR"/
        moved+=("$base")
      fi
    fi
  done
done
shopt -u nullglob

# Also move any other directories in Downloads that look like tools (optional)
echo
echo "[*] Also scanning Downloads for likely tool directories (common names)..."
shopt -s nullglob
for d in "$DOWNLOADS_DIR"/*; do
  if [ -d "$d" ]; then
    name=$(basename "$d")
    # skip large ISO installers and obvious non-tool files
    case "$name" in
      *.iso|*.deb|kali-*|ubuntu-*|*.zip|Metasploitable*|*.ovpn) continue ;;
    esac
    # If not already moved and not huge system folder, offer to move it automatically
    if [ ! -e "$TARGET_DIR/$name" ]; then
      echo "[+] Moving additional folder: $name"
      mv -n "$d" "$TARGET_DIR"/
      moved+=("$name")
    fi
  fi
done
shopt -u nullglob

# Set ownership to the real user (so they can modify tools)
echo
echo "[*] Setting ownership of $TARGET_DIR to $REAL_USER"
chown -R "$REAL_USER":"$REAL_USER" "$TARGET_DIR"

# Create symlinks for executables inside moved folders
echo
echo "[*] Creating symlinks for detected executables/scripts in $TARGET_DIR -> $BIN_LINK_DIR"
linked=()
for sub in "$TARGET_DIR"/*; do
  # look for common entrypoint names or executables inside the folder
  if [ -d "$sub" ]; then
    base=$(basename "$sub")
    # candidates: direct executable with tool name, files in root, or bin/ subdir
    candidates=(
      "$sub/$base"
      "$sub/$base.py"
      "$sub/$base.sh"
      "$sub/$base.py3"
      "$sub/ghauri.py"
      "$sub/run.py"
      "$sub/xsstrike.py"
      "$sub/subfinder.py"
      "$sub/httpx"
      "$sub/katana"
      "$sub/paramspider.py"
      "$sub/ffuf"
      "$sub/dalfox"
      "$sub/sqlmap.py"
      "$sub/subzy"
      "$sub/403bypasser.py"
    )
    # also check common 'venv/bin/<script>' or 'bin/<script>'
    for c in "${candidates[@]}"; do
      if [ -f "$c" ] && [ -x "$c" ]; then
        ln -sf "$c" "$BIN_LINK_DIR/$(basename "$c")"
        linked+=("$(basename "$c") -> $c")
      fi
    done

    # search for any executable files at top-level and link them by name (careful)
    while IFS= read -r -d '' exe; do
      name=$(basename "$exe")
      # avoid linking bizarre names; only link if name looks like a tool (letters, numbers, -,_)
      if [[ "$name" =~ ^[a-zA-Z0-9_.-]+$ ]]; then
        ln -sf "$exe" "$BIN_LINK_DIR/$name"
        linked+=("$name -> $exe")
      fi
    done < <(find "$sub" -maxdepth 1 -type f -perm /111 -print0 2>/dev/null)
  else
    # if it's a file moved directly into /opt/recon_tools (like a binary)
    if [ -f "$sub" ] && [ -x "$sub" ]; then
      ln -sf "$sub" "$BIN_LINK_DIR/$(basename "$sub")"
      linked+=("$(basename "$sub") -> $sub")
    fi
  fi
done

# Final summary
echo
echo "================= SUMMARY ================="
if [ "${#moved[@]}" -gt 0 ]; then
  echo "Moved items:"
  for i in "${moved[@]}"; do echo "  - $i"; done
else
  if [ $found_any -eq 0 ]; then
    echo "No matching tool folders found in $DOWNLOADS_DIR (patterns: ${patterns[*]})"
  else
    echo "No new items moved."
  fi
fi

if [ "${#skipped[@]}" -gt 0 ]; then
  echo
  echo "Skipped (destination existed):"
  for s in "${skipped[@]}"; do echo "  - $s"; done
fi

if [ "${#linked[@]}" -gt 0 ]; then
  echo
  echo "Created symlinks in $BIN_LINK_DIR:"
  for l in "${linked[@]}"; do echo "  - $l"; done
else
  echo
  echo "No executables detected for symlinking."
fi

echo
echo "[✔] Done. Tools are now in: $TARGET_DIR (owned by $REAL_USER)"
echo "Add /usr/local/bin and your go bin path to your PATH if needed:"
echo "  export PATH=\"\$PATH:/usr/local/bin:\${GOPATH:-$USER_HOME/go}/bin\""
echo "You can run 'ls -la $TARGET_DIR' to inspect moved tools."
echo "If some tools are still missing I can add per-tool install commands."

exit 0
