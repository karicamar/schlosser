#!/usr/bin/env bash
# Contract test against code I did not write: OWASP WebGoat.NET, a deliberately vulnerable ASP.NET Core shop.
# The analyzer is attached to the unmodified project at a pinned commit and must report exactly the
# findings in tools/webgoat-expected.txt. A rule that goes blind, or starts shouting, fails the build.
#
#   bash tools/webgoat-contract.sh
set -euo pipefail

REPO="https://github.com/tobyash86/WebGoat.NET.git"
COMMIT="df29d6f094220b53f7a38b08a184eabce3efc6d0"

here="$(cd "$(dirname "$0")/.." && pwd)"
work="${TMPDIR:-/tmp}/schlosser-webgoat"

dotnet build "$here/src/Schlosser.Analyzers" -c Release -v q --nologo
analyzer="$here/src/Schlosser.Analyzers/bin/Release/netstandard2.0/Schlosser.Analyzers.dll"
if command -v cygpath >/dev/null 2>&1; then analyzer="$(cygpath -w "$analyzer")"; fi

rm -rf "$work"
git init -q "$work"
git -C "$work" remote add origin "$REPO"
git -C "$work" fetch -q --depth 1 origin "$COMMIT"
git -C "$work" checkout -q FETCH_HEAD

# Attach the analyzer without touching the project: MSBuild imports this file after its own targets
cat > "$work/schlosser.targets" <<EOF
<Project>
  <ItemGroup>
    <Analyzer Include="$analyzer" />
  </ItemGroup>
</Project>
EOF
targets="$work/schlosser.targets"
if command -v cygpath >/dev/null 2>&1; then targets="$(cygpath -w "$targets")"; fi

dotnet build "$work/WebGoat.NET/WebGoat.NET.csproj" --no-incremental -v q --nologo \
  "-p:CustomAfterMicrosoftCommonTargets=$targets" \
  "-p:ErrorLog=obj/schlosser.sarif%2Cversion=2.1" \
  -p:TreatWarningsAsErrors=false -p:NuGetAudit=false >/dev/null

node "$here/tools/findings.mjs" "$work/WebGoat.NET/obj/schlosser.sarif" "$work/WebGoat.NET" --all \
  --check "$here/tools/webgoat-expected.txt"
