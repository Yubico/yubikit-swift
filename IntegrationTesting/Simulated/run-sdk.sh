#!/usr/bin/env bash
# Build the normal sample once, then select the twin framework at launch.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
BUILD="$REPO_ROOT/.build/simulated-sdk"

fail() { printf '%s\n' "$*" >&2; exit 1; }

tool() {
    local operation="$1" arguments="$2" exit_code=0
    TOOL_RESULT=$(mktemp "$BUILD/logs/$operation.XXXXXX")
    printf '%s\n' "$operation: $(jq -r '.scheme // .bundleId // "Simulator"' <<< "$arguments")"
    xcodebuildmcp "${WORKFLOW:-simulator}" "$operation" --json "$arguments" --output json > "$TOOL_RESULT" || exit_code=$?
    if [[ "$exit_code" != 0 ]] || ! jq -e '(.didError // .isError // false | not) and ((.data.summary.status // "")!="FAILED")' "$TOOL_RESULT" >/dev/null; then
        if [[ "$operation" == stop ]] && jq -e '[.. | strings | select(contains("found nothing to terminate"))] | length>0' "$TOOL_RESULT" >/dev/null; then
            return 0
        fi
        cat "$TOOL_RESULT" >&2; return 1
    fi
    jq -c '.data.summary.counts // empty' "$TOOL_RESULT"
}

write_workspace() {
    local workspace="$1" package="$2" reference
    mkdir -p "$workspace"
    reference=$(jq -rn --arg path "$package" '$path|@html')
    printf '<Workspace version="1.0"><FileRef location="absolute:%s"/></Workspace>\n' "$reference" \
        > "$workspace/contents.xcworkspacedata"
}

sync_sources() {
    mkdir -p "$2"
    rsync -a --delete --exclude .build --exclude .swiftpm --exclude xcuserdata --exclude /Simulated/ "$1/" "$2/"
}

stage_sdk() {
    local destination="$1" variant="$2" source="${3:-$REPO_ROOT}"
    sync_sources "$source/YubiKit/YubiKit" "$destination/YubiKit/YubiKit"
    sync_sources "$source/YubiKit/IntegrationScenarios" "$destination/YubiKit/IntegrationScenarios"
    cp "$REPO_ROOT/IntegrationTesting/Simulated/SDKPackage.swift" "$destination/Package.swift"
    if [[ "$variant" == twin ]]; then
        sync_sources "$REPO_ROOT/IntegrationTesting/Simulated/Support" "$destination/IntegrationTesting/Simulated/Support"
        sync_sources "$REPO_ROOT/IntegrationTesting/Simulated/Drivers" "$destination/YubiKit/YubiKit/Simulated"
    fi
}

build_twin() {
    local source="$1" workspace="$2" derived="$3"
    write_workspace "$workspace" "$source"
    YUBIKIT_BUILD_TWIN=1 YUBIKIT_TWIN_PATH="$TWIN_PATH" tool build "$(jq -n \
        --arg workspace "$workspace" --arg build "$derived" --arg id "$SIM_ID" \
        '{workspacePath:$workspace,scheme:"YubiKit",derivedDataPath:$build,
          configuration:"Debug",extraArgs:["CODE_SIGNING_ALLOWED=NO"]}
          + (if $id == "" then {} else {simulatorId:$id} end)')"
}

build_app_and_twin() {
    local real="$APP_BUILD/source/real" twin="$APP_BUILD/source/twin"
    local workspace="$APP_BUILD/TwinSDK.xcworkspace"

    rm -f "$APP_BUILD/ready"
    stage_sdk "$real" real
    stage_sdk "$twin" twin "$real"
    sync_sources "$REPO_ROOT/$APP_SOURCE" "$real/$APP_SOURCE"

    # The staged framework contains both the SDK and the shared scenario module.
    if [[ "$APP_NAME" == IntegrationTesting ]]; then
        sed -i '' 's/productName = YubiKitIntegrationScenarios;/productName = YubiKit;/' \
            "$real/$APP_SOURCE/$APP_NAME.xcodeproj/project.pbxproj"
    fi
    YUBIKIT_BUILD_TWIN=0 tool build "$(jq -n \
        --arg project "$real/$APP_SOURCE/$APP_NAME.xcodeproj" --arg scheme "$APP_NAME" \
        --arg build "$APP_BUILD/real" --arg id "$SIM_ID" \
        '{projectPath:$project,scheme:$scheme,derivedDataPath:$build,
          configuration:"Debug",extraArgs:["CODE_SIGNING_ALLOWED=NO"]}
          + (if $id == "" then {} else {simulatorId:$id} end)')"
    build_twin "$twin" "$workspace" "$APP_BUILD/twin"
    touch "$APP_BUILD/ready"
}

launch_sample() {
    local real="$APP_BUILD/real/Build/Products/$PRODUCTS_DIRECTORY"
    local products="$APP_BUILD/twin/Build/Products/$PRODUCTS_DIRECTORY"
    local app="$real/$APP_NAME.app" executable="$real/$APP_NAME"
    [[ -f "$APP_BUILD/ready" && -f "$products/PackageFrameworks/YubiKit.framework/YubiKit" ]] \
        || fail 'Use run to build the sample and its TwinKit framework first'
    if [[ "$WORKFLOW" == macos ]]; then
        if [[ "$SAMPLE" != piv ]]; then
            executable="$app/Contents/MacOS/$(plutil -extract CFBundleExecutable raw "$app/Contents/Info.plist")"
        fi
        [[ -x "$executable" ]] || fail "Missing sample executable: $executable"
        DYLD_FRAMEWORK_PATH="$products/PackageFrameworks" PACKAGE_RESOURCE_BUNDLE_PATH="$products" \
            YUBIKIT_TWIN_PROFILE="$PROFILE" YUBIKIT_TWIN_TRANSPORT="$TRANSPORT" YUBIKIT_TWIN_NFC_READER="$NFC_READER" \
            "$executable" "$@"
        return
    fi

    [[ -f "$app/Info.plist" ]] || fail 'Use run to build the sample and its TwinKit framework first'
    local bundle arguments
    bundle=$(plutil -extract CFBundleIdentifier raw "$app/Info.plist")
    arguments=$(jq -n --arg id "$SIM_ID" --arg bundle "$bundle" '{simulatorId:$id,bundleId:$bundle}')

    tool list '{}'
    if ! jq -e --arg id "$SIM_ID" '.data.simulators[] | select(.simulatorId==$id and .state=="Booted")' "$TOOL_RESULT" >/dev/null; then
        tool boot "$(jq -n --arg id "$SIM_ID" '{simulatorId:$id}')"
    fi
    tool stop "$arguments"
    tool install "$(jq -n --arg id "$SIM_ID" --arg app "$app" '{simulatorId:$id,appPath:$app}')"

    printf 'Launching %s with the TwinKit framework\n' "$APP_NAME"
    arguments=$(jq --arg products "$products" --arg profile "$PROFILE" --arg transport "$TRANSPORT" --arg reader "$NFC_READER" \
        '.+{env:{DYLD_FRAMEWORK_PATH:($products+"/PackageFrameworks"),PACKAGE_RESOURCE_BUNDLE_PATH:$products,
                 YUBIKIT_TWIN_PROFILE:$profile,YUBIKIT_TWIN_TRANSPORT:$transport,
                 YUBIKIT_TWIN_NFC_READER:$reader}}' <<< "$arguments")
    tool launch-app "$arguments"
    jq '.data.artifacts' "$TOOL_RESULT"
}

run_scenarios() {
    local output="$BUILD/scenarios-$WORKFLOW"
    local real="$output/source/real" twin="$output/source/twin"
    local workspace="$output/IntegrationScenarios.xcworkspace" products arguments

    stage_sdk "$real" real
    stage_sdk "$twin" twin "$real"
    sync_sources "$REPO_ROOT/IntegrationTesting/Tests" "$real/IntegrationTesting/Tests"
    sed '/\.product(name: "YubiKitIntegrationScenarios"/d' "$REPO_ROOT/IntegrationTesting/Package.swift" \
        > "$real/IntegrationTesting/Package.swift"
    write_workspace "$workspace" "$real/IntegrationTesting"
    build_twin "$twin" "$output/TwinSDK.xcworkspace" "$output/twin"

    products="$output/twin/Build/Products/$PRODUCTS_DIRECTORY"
    arguments=$(jq -n --arg w "$workspace" --arg id "$SIM_ID" --arg d "$output/real" \
        --arg products "$products" --arg profile "$PROFILE" --arg transport "$TRANSPORT" \
        --arg reader "$NFC_READER" --args '
        {workspacePath:$w,scheme:"IntegrationTests",derivedDataPath:$d,
         configuration:"Debug",extraArgs:(["CODE_SIGNING_ALLOWED=NO"] + $ARGS.positional),
         testRunnerEnv:((env | {SCENARIO, FORCE_SCP} | with_entries(select(.value != null)))
                       + {DYLD_FRAMEWORK_PATH:($products+"/PackageFrameworks"),
                          PACKAGE_RESOURCE_BUNDLE_PATH:$products,YUBIKIT_TWIN_PROFILE:$profile,
                          YUBIKIT_TWIN_TRANSPORT:$transport,YUBIKIT_TWIN_NFC_READER:$reader,
                          YUBIKIT_TEST_TRANSPORT:$transport,YUBIKIT_REQUIRE_VIRTUAL_KEY:"1"})}
         + (if $id == "" then {} else {simulatorId:$id} end)' -- "$@")
    unset YUBIKEY_TEST_SERIALS
    YUBIKIT_BUILD_TWIN=0 tool test "$arguments"
}

usage() {
    printf 'Usage: %s <run|launch|scenarios> [--simulator-id UUID] [--sample oath|webauthn|integration|piv] [--twin-path PATH] [--transport usb|nfc] [--profile PROFILE] [--no-nfc-reader] [-- ARGS...]\n' "$0"
    printf 'Omit --simulator-id to run on macOS. Extra arguments go to the PIV CLI or Xcode tests.\n'
}

main() {
    COMMAND=${1:-}; [[ -z "$COMMAND" ]] || shift
    SAMPLE=oath; SIM_ID=''; TWIN_PATH=${YUBIKIT_TWIN_PATH:-}; TRANSPORT=usb; PROFILE=5-nfc; NFC_READER=1
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --sample) SAMPLE=${2:?Missing sample}; shift 2 ;;
            --simulator-id) SIM_ID=${2:?Missing Simulator ID}; shift 2 ;;
            --twin-path) TWIN_PATH=${2:?Missing TwinKit path}; shift 2 ;;
            --transport) TRANSPORT=${2:?Missing transport}; shift 2 ;;
            --profile) PROFILE=${2:?Missing profile}; shift 2 ;;
            --no-nfc-reader) NFC_READER=0; shift ;;
            --) shift; break ;;
            -h|--help) usage; return ;;
            *) fail "Unknown argument: $1" ;;
        esac
    done
    case "$COMMAND" in run|launch|scenarios) ;; -h|--help) usage; return ;; *) usage; return 1 ;; esac
    WORKFLOW=macos; PRODUCTS_DIRECTORY=Debug
    if [[ -n "$SIM_ID" ]]; then
        [[ "$SIM_ID" =~ ^[[:xdigit:]]{8}(-[[:xdigit:]]{4}){3}-[[:xdigit:]]{12}$ ]] || fail '--simulator-id must be a UUID'
        SIM_ID=$(tr '[:lower:]' '[:upper:]' <<< "$SIM_ID")
        WORKFLOW=simulator; PRODUCTS_DIRECTORY=Debug-iphonesimulator
    fi
    case "$SAMPLE" in
        oath) APP_NAME=OATHSample; APP_SOURCE=Samples/OATHSample ;;
        webauthn) APP_NAME=WebAuthnInterceptorSample; APP_SOURCE=Samples/WebAuthnInterceptorSample ;;
        integration) APP_NAME=IntegrationTesting; APP_SOURCE=IntegrationTesting ;;
        piv)
            [[ "$WORKFLOW" == macos && "$COMMAND" != scenarios ]] || fail 'The PIV CLI requires run or launch on macOS'
            APP_NAME=yubikit-piv-tool; APP_SOURCE=Samples/yubikit-piv-tool
            ;;
        *) fail 'Sample must be oath, webauthn, integration, or piv' ;;
    esac
    case "$TRANSPORT" in usb|nfc) ;; *) fail 'Transport must be usb or nfc' ;; esac
    command -v jq >/dev/null || fail 'jq is required'
    command -v xcodebuildmcp >/dev/null || fail 'xcodebuildmcp is required'
    mkdir -p "$BUILD/logs"
    LOCK="$BUILD/$WORKFLOW.lock"
    if [[ "$WORKFLOW" == macos && "$COMMAND" != scenarios ]]; then
        LOCK="$BUILD/$WORKFLOW-$APP_NAME.lock"
    fi
    mkdir "$LOCK" 2>/dev/null || fail "TwinKit SDK helper is busy: $LOCK"
    trap 'rmdir "$LOCK"' EXIT
    if [[ -n "$TWIN_PATH" ]]; then
        TWIN_PATH=$(cd "$TWIN_PATH" && pwd -P)
        [[ -f "$TWIN_PATH/Package.swift" && ${TWIN_PATH##*/} == hardware-digital-twin ]] || fail 'Invalid TwinKit checkout'
    fi
    if [[ "$COMMAND" == scenarios ]]; then
        run_scenarios "$@"
        return
    fi
    APP_BUILD="$BUILD/$APP_NAME"
    [[ "$WORKFLOW" != macos ]] || APP_BUILD="$BUILD/$WORKFLOW/$APP_NAME"
    [[ "$SAMPLE" == piv || $# -eq 0 ]] || fail 'Extra arguments require the PIV CLI or scenarios command'
    if [[ "$COMMAND" == run ]]; then build_app_and_twin >&2; fi
    launch_sample "$@"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
