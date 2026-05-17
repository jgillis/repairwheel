import argparse
import logging
from pathlib import Path
from typing import List

from packaging.utils import parse_wheel_filename

from . import monkeypatch
from . import patcher

log = logging.getLogger(__name__)


def get_machine_from_wheel(wheel: Path) -> str:
    _, _, _, tags = parse_wheel_filename(wheel.name)
    tags = list(tags)
    first_tag = next(iter(tags))
    if len(tags) > 1:
        log.warning("Wheel %s has multiple tags; using first (%s)", wheel.name, first_tag)

    # platform is like 'linux_x86_64', 'manylinux2014_aarch64',
    # 'manylinux_2_28_aarch64', etc. We can't simply split on '_'
    # because PEP 600 manylinux tags embed an underscore-separated
    # version number (e.g. manylinux_2_28_<arch>). Match against the
    # known architecture suffixes instead.
    plat = first_tag.platform
    for arch in ("x86_64", "i686", "aarch64", "armv7l", "ppc64le", "ppc64", "s390x"):
        if plat.endswith("_" + arch):
            return arch
    return plat.rsplit("_", 1)[-1]


def repair(wheel_file: Path, output_dir: Path, lib_path: List[Path], use_sys_paths: bool, exclude: List[str], verbosity: int = 0) -> None:
    target_machine = get_machine_from_wheel(wheel_file)
    monkeypatch.apply_auditwheel_patches(target_machine, lib_path, use_sys_paths)

    from repairwheel._vendor.auditwheel.policy import WheelPolicies
    from repairwheel._vendor.auditwheel.wheel_abi import analyze_wheel_abi, NonPlatformWheel

    try:
        winfo = analyze_wheel_abi(WheelPolicies(), str(wheel_file), frozenset())
    except NonPlatformWheel:
        log.info(NonPlatformWheel.LOG_MESSAGE)
        return

    show_parser = argparse.ArgumentParser()
    show_sub_parsers = show_parser.add_subparsers(metavar="command", dest="cmd")

    repair_parser = argparse.ArgumentParser()
    repair_sub_parsers = repair_parser.add_subparsers(metavar="command", dest="cmd")

    from repairwheel._vendor.auditwheel import main_repair, main_show

    main_repair.Patchelf = patcher.RepairWheelElfPatcher

    main_show.configure_parser(show_sub_parsers)
    main_repair.configure_parser(repair_sub_parsers)

    show_args = show_parser.parse_args(["show", str(wheel_file)])
    show_args.verbose = verbosity
    show_args.func(show_args, show_parser)

    excludes = []
    for e in exclude:
        excludes+=["--exclude", e]

    # Use the wheel's claimed platform tag for --plat, not winfo.sym_tag.
    #
    # winfo.sym_tag is the analyzed tag, which auditwheel will silently
    # downgrade (e.g. manylinux_2_28_aarch64 -> linux_aarch64) whenever
    # the wheel references any versioned symbol that exceeds the policy
    # ceiling. The most common trigger today is libstdc++ GLIBCXX > 3.4.24
    # under manylinux_2_28 from a gcc-12+ aarch64 cross-toolchain.
    #
    # Under the "linux" fallback policy the lib_whitelist is empty, so
    # every DT_NEEDED (including libpthread.so.0, libc.so.6, libm.so.6,
    # libdl.so.2, librt.so.1) gets bundled into the wheel. The bundled
    # glibc-2.X libpthread is then unloadable on glibc-2.34+ targets
    # because the libpthread->libc merge in glibc 2.34 removed
    # `_dl_make_stack_executable@GLIBC_PRIVATE` in favor of
    # `__nptl_change_stack_perm@GLIBC_PRIVATE`. The wheel installs fine
    # but ImportError-s at load time with
    #   undefined symbol: _dl_make_stack_executable, version GLIBC_PRIVATE
    #
    # The native-arch auditwheel path papers over this with
    # `--no-update-tags`. To get parity here we have to (a) pass the
    # original tag via --plat so auditwheel uses that policy's whitelist
    # for bundling decisions, (b) override the analyzed tags inside the
    # wheel-abi info object so main_repair.py's
    #     if reqd_tag > get_priority_by_name(wheel_abi.sym_tag):
    #         p.error("too-recent versioned symbols")
    # guard passes, and (c) pass --no-update-tags so the output wheel
    # keeps the original filename tag.
    _, _, _, _tags = parse_wheel_filename(wheel_file.name)
    original_plat = next(iter(_tags)).platform

    from repairwheel._vendor.auditwheel import wheel_abi as _wabi
    _orig_analyze_wheel_abi = _wabi.analyze_wheel_abi

    def _analyze_wheel_abi_keep_plat(wheel_policy, wheel_fn, exclude):
        info = _orig_analyze_wheel_abi(wheel_policy, wheel_fn, exclude)
        try:
            return info._replace(
                sym_tag=original_plat,
                overall_tag=original_plat,
                ucs_tag=original_plat,
                blacklist_tag=original_plat,
            )
        except AttributeError:
            for f in ("sym_tag", "overall_tag", "ucs_tag", "blacklist_tag"):
                try:
                    object.__setattr__(info, f, original_plat)
                except (AttributeError, TypeError):
                    pass
            return info

    _wabi.analyze_wheel_abi = _analyze_wheel_abi_keep_plat
    try:
        repair_args = repair_parser.parse_args(
            [
                "repair",
                str(wheel_file),
                "--only-plat",
                "-L", ".",
                "--plat",
                original_plat,
                "--no-update-tags",
                "--wheel-dir",
                str(output_dir),
            ]+excludes
        )
        repair_args.verbose = verbosity
        repair_args.func(repair_args, repair_parser)
    finally:
        _wabi.analyze_wheel_abi = _orig_analyze_wheel_abi
