#/bin/sh
#/
#/ usage: ./bundle.sh [ --zip ] <output-dir> <release-dir> <version> <platform> <architecture> <executable-name>
#/
#/  Flags:
#/   --zip:         unique name of the module
#/   -h, --help:    print usage info
#/
#/  Positional Args:
#/   output-dir:
#/   release-dir:
#/   version:
#/   platform:
#/   architecture:
#/   executable-name:
#/
#/  Examples:
#/   ./bundle.sh ./output/binary/linux ./travis-releases 0.14.1-rc.5 linux amd64 step
#/   ./bundle.sh --zip ./output/binary/windows ./travis-releases 0.14.1-rc.5 windows amd64 step.exe
#/

usage() {
    cat "$0" | grep '^#/' | cut -c 4-
    echo "Exiting with $1"
    exit $1
}

ZIP=0
while [ $# -gt 0 ]
do
    case "$1" in
        "--zip") ZIP=1; shift 1;;
        "-h"|"--help") usage 0;;
        "--") break;;
        *) break;;
    esac
done
set -ex;

OUTPUT_DIR=$1
RELEASE_DIR=$2

STEP_VERSION=$3
STEP_PLATFORM=$4
STEP_ARCH=$5
STEP_EXEC_NAME=$6

BUNDLE_DIR=${OUTPUT_DIR}/bundle

mkdir -p "$BUNDLE_DIR" "$RELEASE_DIR"
TMP=$(mktemp -d "$BUNDLE_DIR/tmp.XXXX")
trap "rm -rf $TMP" EXIT INT QUIT TERM

stepName=step_${STEP_VERSION}
newdir="$TMP/${stepName}"
mkdir -p "$newdir/bin"

cp "$OUTPUT_DIR/bin/step" "$newdir/bin/${STEP_EXEC_NAME}"
cp README.md "$newdir"

if [ ${ZIP} -eq 0 ]; then
    NEW_BUNDLE="${RELEASE_DIR}/step_${STEP_PLATFORM}_${STEP_VERSION}_${STEP_ARCH}.tar.gz"

    rm -f "$NEW_BUNDLE"
    tar -zcvf "$NEW_BUNDLE" -C "$TMP" "${stepName}"
else
    NEW_BUNDLE="${RELEASE_DIR}/step_${STEP_PLATFORM}_${STEP_VERSION}_${STEP_ARCH}.zip"

    rm -f "${NEW_BUNDLE}"
    zip -jr "${NEW_BUNDLE}" "${TMP}"
fi
