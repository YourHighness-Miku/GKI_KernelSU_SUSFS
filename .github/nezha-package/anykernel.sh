#!/sbin/sh
properties() { '
kernel.string=Nezha r74 Nova SUSFS DroidSpaces Networking BBG
do.devicecheck=1
do.modules=0
do.systemless=0
do.cleanup=1
do.cleanuponabort=0
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

block=boot
is_slot_device=1
slot_select=active
ramdisk_compression=auto
patch_vbmeta_flag=0
no_magisk_check=1
export PATCHVBMETAFLAG=false
export NO_VBMETA_PARTITION_PATCH=1

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
vendor_patch=$(read_vendor_patch /vendor/build.prop) || exit 1
vendor_patch_allowed "$vendor_patch" || exit 1

expected_image=278e05748f16841f4cc86cd33954e065acef0e34038a949385dd196c1219a47c
actual_image=$(sha256sum "$AKHOME/Image") || exit 1
actual_image=${actual_image%% *}
[ "$actual_image" = "$expected_image" ] || exit 1

. tools/ak3-core.sh

case "$SLOT" in
  _a|_b) ;;
  *) abort "Invalid active A/B slot; refusing to write." ;;
esac
case "$BLOCK" in
  /dev/block/by-name/boot"$SLOT"|/dev/block/bootdevice/by-name/boot"$SLOT") ;;
  *) abort "Unexpected target; only the active boot partition is permitted." ;;
esac

split_boot
[ ! -s "$SPLITIMG/ramdisk.cpio" ] || abort "Unexpected boot ramdisk for this public reference."
flash_boot
