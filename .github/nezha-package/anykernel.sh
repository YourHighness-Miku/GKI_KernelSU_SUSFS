#!/sbin/sh
properties() { '
kernel.string=Nezha r74 Nova SUSFS DroidSpaces Networking BBG
do.devicecheck=1
do.modules=0
do.systemless=0
do.cleanup=1
do.cleanuponabort=1
do.check_boot_version=1
device.name1=nezha
device.name2=
device.name3=
device.name4=
device.name5=
supported.versions=17
supported.patchlevels=
supported.vendorpatchlevels=2026-10 - 2026-10
'; }

vendor_patch_allowed() {
  case "$1" in
    2026-10-0[1-9]|2026-10-[12][0-9]|2026-10-3[01]) return 0 ;;
    *) return 1 ;;
  esac
}
read_vendor_patch() {
  awk '
    /^ro.vendor.build.security_patch=/ { count++; value=substr($0, index($0, "=") + 1) }
    END { if (count != 1) exit 1; print value }
  ' "$1"
}
unlocked_values_allowed() {
  [ "$1:$2:$3:$4" = '0:unlocked:0:unlocked' ]
}
slots_agree() {
  case "$1" in _a|_b) ;; *) return 1 ;; esac
  [ "$1" = "$2" ] && { [ -z "$3" ] || [ "$3" = "${1#_}" ]; }
}
boot_record() {
  case "$3" in
    config)
      awk -v key="$2" '
        $1 == key && $2 == "=" {
          n++; if (NF != 3) bad=1; v=$3; gsub(/^"|"$/, "", v)
        }
        END { if (n > 1 || bad || (n && v == "")) exit 1; if (n) print v }
      ' "$1"
      ;;
    cmdline)
      awk -v key="$2" '
        { for (i=1;i<=NF;i++) if (index($i,key "=")==1) { n++;v=substr($i,length(key)+2) } }
        END { if (n>1 || (n && v == "")) exit 1; if(n) print v }
      ' "$1"
      ;;
    *) return 1 ;;
  esac
}
boot_value() {
  local key="$1" source value format combined=''
  for source in /proc/bootconfig /proc/cmdline; do
    [ -r "$source" ] || continue
    case "$source" in /proc/bootconfig) format=config ;; *) format=cmdline ;; esac
    value=$(boot_record "$source" "$key" "$format") || return 1
    [ -n "$value" ] || continue
    [ -z "$combined" ] || [ "$combined" = "$value" ] || return 1
    combined="$value"
  done
  printf '%s' "$combined"
}
current_slot() {
  local prop proc letter prop_letter device version locked state raw_locked raw_state
  device=$("$PROP_TOOL" ro.product.device) || return 1
  version=$("$PROP_TOOL" ro.build.version.release) || return 1
  [ "$device:$version" = nezha:17 ] || return 1
  locked=$("$PROP_TOOL" ro.boot.flash.locked) || return 1
  state=$("$PROP_TOOL" ro.boot.vbmeta.device_state) || return 1
  raw_locked=$(boot_value androidboot.flash.locked) || return 1
  raw_state=$(boot_value androidboot.vbmeta.device_state) || return 1
  unlocked_values_allowed "$locked" "$state" "$raw_locked" "$raw_state" || return 1
  prop=$("$PROP_TOOL" ro.boot.slot_suffix) || return 1
  proc=$(boot_value androidboot.slot_suffix) || return 1
  letter=$(boot_value androidboot.slot) || return 1
  [ -n "$proc" ] || { case "$letter" in a|b) proc="_$letter" ;; *) return 1 ;; esac; }
  slots_agree "$prop" "$proc" "$letter" || return 1
  prop_letter=$("$PROP_TOOL" ro.boot.slot) || return 1
  [ -z "$prop_letter" ] || [ "$prop_letter" = "${prop#_}" ] || return 1
  printf '%s' "$prop"
}
partition_label() {
  awk -F= '$1 == "PARTNAME" { n++; if(NF != 2 || $2 == "") bad=1; v=$2 }
    END { if(n != 1 || bad) exit 1; print v }' "$1"
}
partition_node() {
  local name="$1" suffix="${2:-$FROZEN_SLOT}" alias node identity major minor label ro chosen=''
  for alias in "/dev/block/by-name/$name$suffix" "/dev/block/bootdevice/by-name/$name$suffix"; do
    [ -e "$alias" ] || continue
    node=$(readlink -f "$alias") || return 1
    case "$node" in /dev/block/*) ;; *) return 1 ;; esac
    case "$node" in *' '*|*'
'*) return 1 ;; esac
    [ -b "$node" ] || return 1
    identity=$(stat -L -c '%t:%T' "$node") || return 1
    major=${identity%:*}; minor=${identity#*:}
    case "$major:$minor" in *[!0-9a-f:]*) return 1 ;; esac
    [ -n "$major" ] && [ -n "$minor" ] || return 1
    label=$(partition_label "/sys/dev/block/$((0x$major)):$((0x$minor))/uevent") || return 1
    if [ "$name:$suffix" = "boot:$FROZEN_SLOT" ]; then
      ro=$(cat "/sys/dev/block/$((0x$major)):$((0x$minor))/ro") || return 1
      [ "$ro" = 0 ] || return 1
    fi
    [ "$label" = "$name$suffix" ] || return 1
    [ -z "$chosen" ] || [ "$chosen" = "$node" ] || return 1
    chosen="$node"
  done
  [ -n "$chosen" ] || return 1
  printf '%s' "$chosen"
}
reference_identities() {
  local name bytes expected coverage node capacity actual identity other other_id opposite
  case "$FROZEN_SLOT" in _a) opposite=_b ;; _b) opposite=_a ;; *) return 1 ;; esac
  while read -r name bytes expected coverage; do
    node=$(partition_node "$name") || return 1
    capacity=$(blockdev --getsize64 "$node") || return 1
    case "$capacity" in ''|*[!0-9]*) return 1 ;; esac
    if [ "$coverage" = full ]; then
      [ "$capacity" = "$bytes" ] || return 1
    else
      [ "$capacity" -ge "$bytes" ] || return 1
    fi
    actual=$(dd if="$node" bs=4096 count="$((bytes / 4096))" 2>/dev/null | sha256sum) || return 1
    [ "${actual%% *}" = "$expected" ] || return 1
    identity=$(stat -L -c '%t:%T' "$node") || return 1
    other=$(partition_node "$name" "$opposite") || return 1
    other_id=$(stat -L -c '%t:%T' "$other") || return 1
    [ "$other" != "$node" ] && [ "$other_id" != "$identity" ] || return 1
    printf '%s %s %s %s %s\n' "$name" "$node" "$identity" "$capacity" "$other_id"
  done <<'REFERENCES'
boot 100663296 1f7a147e34b6ca82621a194b3b6fa54735ae2236e34c65c42df41ec05422e832 full
init_boot 8388608 1f5105d5fba35d5a6ef14a429de595a7149044dcac2b90e74a18ac413b9933f2 full
vendor_boot 100663296 68a80b12e8210e0683fb0f275e0df2134db591113c9d6d91acbd34f54f4409cf full
vbmeta 12288 dcb74c3deca0b406b04b6892035f91c2c59475b69dc42857c3d9439a512bed78 prefix
vbmeta_system 4096 ada7f6370b2821c02f4b2832cba224472ca66decdcc9c1f9a1c35d32d6e515a7 prefix
abl 335872 9f6a3bd6ec3c2785b2fab8101c779990cb85fc7c3de7bead2798f015b8c2da50 prefix
uefi 2793472 04ae90ea829ff2fadc0f98e6e947d1edc6258f16ce2dea2dacd449fecf95b1af prefix
xbl_config 397312 2ee3834fee96cb9a1ee70861c688f361c6decaa639452a74d7f45d774a9180bd prefix
REFERENCES
}
nezha_write_verified() {
  local actual current
  [ "$(current_slot)" = "$FROZEN_SLOT" ] || abort 'Boot state changed; refusing write.'
  current=$(reference_identities) || abort 'Reference state changed; refusing write.'
  [ "$current" = "$FROZEN_IDENTITIES" ] || abort 'Partition identities changed; refusing write.'
  [ "$(readlink -f "$BLOCK")" = "$FROZEN_BOOT" ] || abort 'Target changed; refusing write.'
  [ -f "$AKHOME/boot-new.img" ] && [ ! -L "$AKHOME/boot-new.img" ] || abort 'Invalid output image.'
  [ "$(wc -c < "$AKHOME/boot-new.img")" -eq 100663296 ] || abort 'Output geometry differs.'
  actual=$(sha256sum "$AKHOME/boot-new.img") || abort 'Cannot hash output.'
  [ "${actual%% *}" = "$EXPECTED_REPACKED_SHA256" ] || abort 'Output differs from the accepted offline transformation.'
  [ "$(current_slot)" = "$FROZEN_SLOT" ] || abort 'Boot state changed before write.'
  [ "$(partition_node boot)" = "$FROZEN_BOOT" ] || abort 'Target changed before write.'
  mkdir "$AKHOME/write-gate" 2>/dev/null || abort 'Cancelled before write or write already committed.'
  trap '' HUP INT TERM
  dd if="$AKHOME/boot-new.img" of="$FROZEN_BOOT" bs=1048576 conv=fsync || abort 'Boot write failed; no automatic retry.'
  sync || abort 'Sync failed; no automatic retry.'
  actual=$(sha256sum "$FROZEN_BOOT") || abort 'Readback failed; no automatic retry.'
  [ "${actual%% *}" = "$EXPECTED_REPACKED_SHA256" ] || abort 'Readback mismatch; no automatic retry.'
}

cancel_before_commit() {
  mkdir "$AKHOME/write-gate" 2>/dev/null || :
  : > "$AKHOME/cancel-requested"
}

# entrypoint
set -o pipefail || exit 1
unset magisk_patched customdd CUSTOMDD BLOCK SLOT IS_SLOT_DEVICE SLOT_SELECT RAMDISK_COMPRESSION PATCH_VBMETA_FLAG
unset KEEPVERITY KEEPFORCEENCRYPT RECOVERYMODE PREINITDEVICE LD_PRELOAD LD_LIBRARY_PATH LD_CONFIG_FILE
case "$EXPECTED_REPACKED_SHA256" in ''|*[!0-9a-f]*) exit 1 ;; esac
[ "${#EXPECTED_REPACKED_SHA256}" = 64 ] || exit 1
[ -n "$AKHOME" ] && [ -d "$AKHOME" ] || exit 1
trap cancel_before_commit HUP INT TERM
PROP_TOOL=/system/bin/getprop
[ -x "$PROP_TOOL" ] || PROP_TOOL=/sbin/getprop
[ -x "$PROP_TOOL" ] || exit 1
vendor_patch=$(read_vendor_patch /vendor/build.prop) || exit 1
vendor_patch_allowed "$vendor_patch" || exit 1
FROZEN_SLOT=$(current_slot) || exit 1
FROZEN_IDENTITIES=$(reference_identities) || exit 1
FROZEN_BOOT=$(partition_node boot) || exit 1
readonly FROZEN_SLOT FROZEN_IDENTITIES FROZEN_BOOT PROP_TOOL EXPECTED_REPACKED_SHA256 AKHOME
getprop() { "$PROP_TOOL" "$@"; }
expected_image=278e05748f16841f4cc86cd33954e065acef0e34038a949385dd196c1219a47c
actual_image=$(sha256sum "$AKHOME/Image") || exit 1
actual_image=${actual_image%% *}
[ "$actual_image" = "$expected_image" ] || exit 1
block=boot
is_slot_device=1
slot_select=active
ramdisk_compression=auto
patch_vbmeta_flag=0
no_magisk_check=1
magisk_patched=0
export PATCHVBMETAFLAG=false
export NO_VBMETA_PARTITION_PATCH=1
. tools/ak3-core.sh
[ "$SLOT" = "$FROZEN_SLOT" ] || abort 'Core slot differs.'
[ "$(readlink -f "$BLOCK")" = "$FROZEN_BOOT" ] || abort 'Core target differs.'
ui_print 'Only the pinned public OTA on an already-unlocked nezha is supported.'
ui_print 'OEM signature bytes are preserved; the new kernel is not OEM content-authenticated.'
split_boot
actual_image=$(sha256sum "$BOOTIMG") || abort 'Cannot hash dumped boot.'
[ "${actual_image%% *}" = 1f7a147e34b6ca82621a194b3b6fa54735ae2236e34c65c42df41ec05422e832 ] || abort 'Dumped boot differs.'
[ ! -s "$SPLITIMG/ramdisk.cpio" ] || abort 'Unexpected boot ramdisk.'
flash_boot
