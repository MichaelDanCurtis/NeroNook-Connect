#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Only public client configuration is included. No credentials from Keychain.
test -f Resources/Service.json
swift build -c release --arch arm64 --arch x86_64
product_dir="$(swift build -c release --show-bin-path)"
mkdir -p "$PWD/dist"
staging_dir="$(mktemp -d "$PWD/dist/.connect-package.XXXXXX")"
trap 'rm -rf "$staging_dir"' EXIT
app_dir="$staging_dir/Nero Connect.app"
mkdir -p "$app_dir/Contents/MacOS" "$app_dir/Contents/Resources/ThirdParty"
cp "$product_dir/NeroConnect" "$app_dir/Contents/MacOS/NeroConnect"
cp Resources/Service.json "$app_dir/Contents/Resources/Service.json"
for bundle in "$product_dir"/*.bundle; do
    if test -d "$bundle"; then ditto "$bundle" "$app_dir/Contents/Resources/$(basename "$bundle")"; fi
done
CONNECT_STAGING_APP="$app_dir" python3 - <<'PY'
import pathlib,plistlib
root=pathlib.Path.cwd(); import os
contents=pathlib.Path(os.environ['CONNECT_STAGING_APP'])/'Contents'
info={'CFBundleIdentifier':'cafe.nero.connect','CFBundleName':'Nero Connect','CFBundleDisplayName':'Nero Connect',
 'CFBundleExecutable':'NeroConnect','CFBundlePackageType':'APPL','CFBundleShortVersionString':'0.1.1',
 'CFBundleVersion':'2','LSMinimumSystemVersion':'14.0','LSUIElement':True,
 'CFBundleURLTypes':[{'CFBundleURLName':'cafe.nero.connect.signin','CFBundleURLSchemes':['cafe.nero.connect']}]}
(contents/'Info.plist').write_bytes(plistlib.dumps(info))
for checkout in (root/'.build/checkouts').iterdir():
 for name in ['LICENSE','LICENSE.txt','NOTICE','NOTICE.txt','COPYING']:
  source=checkout/name
  if source.exists(): (contents/'Resources/ThirdParty'/f'{checkout.name}-{name}.txt').write_bytes(source.read_bytes())
for source in (root/'.build/checkouts/swift-crypto/Sources').glob('**/LICENSE'):
 name='swift-crypto-'+str(source.relative_to(root/'.build/checkouts/swift-crypto/Sources')).replace('/','-')+'.txt'
 (contents/'Resources/ThirdParty'/name).write_bytes(source.read_bytes())
PY
signing_identity="${NERO_CONNECT_SIGN_IDENTITY:-CE75496A5DF58667917C658976A59F07D784F39E}"
codesign --force --sign "$signing_identity" --options runtime --timestamp=none "$app_dir"
codesign --verify --strict "$app_dir"
ditto -c -k --sequesterRsrc --keepParent "$app_dir" "$PWD/dist/Nero-Connect-0.1.1-local.zip"
# Preserve any running app's mapped files. Publish a separate versioned local bundle.
final_dir="$PWD/dist/Nero Connect 0.1.1.app"
if test -d "$final_dir"; then mv "$final_dir" "$staging_dir/Previous.app"; fi
mv "$app_dir" "$final_dir"
shasum -a 256 "$PWD/dist/Nero-Connect-0.1.1-local.zip"
