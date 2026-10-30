const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const linkage = b.option(std.builtin.LinkMode, "linkage", "Link mode (.static or .shared)") orelse .static;

    const lib = b.addLibrary(.{
        .linkage = linkage,
        .name = "omnisec-ml-runtime",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    // Add extra source files as modules so they get compiled into the lib
    lib.root_module.addImport("spmv", b.createModule(.{
        .root_source_file = b.path("src/spmv.zig"),
        .target = target,
        .optimize = optimize,
    }));

    lib.root_module.addImport("batch_inference", b.createModule(.{
        .root_source_file = b.path("src/batch_inference.zig"),
        .target = target,
        .optimize = optimize,
    }));

    lib.root_module.addImport("hdc_train", b.createModule(.{
        .root_source_file = b.path("src/hdc_train.zig"),
        .target = target,
        .optimize = optimize,
    }));

    b.installArtifact(lib);

    // ── Tests ────────────────────────────────────────────────────────────
    const main_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    main_tests.root_module.addImport("spmv", b.createModule(.{
        .root_source_file = b.path("src/spmv.zig"),
        .target = target,
        .optimize = optimize,
    }));
    main_tests.root_module.addImport("batch_inference", b.createModule(.{
        .root_source_file = b.path("src/batch_inference.zig"),
        .target = target,
        .optimize = optimize,
    }));
    main_tests.root_module.addImport("hdc_train", b.createModule(.{
        .root_source_file = b.path("src/hdc_train.zig"),
        .target = target,
        .optimize = optimize,
    }));

    const spmv_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/spmv.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const batch_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/batch_inference.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const hdc_train_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/hdc_train.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_main_tests = b.addRunArtifact(main_tests);
    const run_spmv_tests = b.addRunArtifact(spmv_tests);
    const run_batch_tests = b.addRunArtifact(batch_tests);
    const run_hdc_train_tests = b.addRunArtifact(hdc_train_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
    test_step.dependOn(&run_spmv_tests.step);
    test_step.dependOn(&run_batch_tests.step);
    test_step.dependOn(&run_hdc_train_tests.step);

    // ── APK Patch Editor Executable ──────────────────────────────────────
    const apk_exe = b.addExecutable(.{
        .name = "apk-editor",
        .root_module = b.createModule(.{
            .root_source_file = b.path("apk_editor/src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    if (target.result.os.tag == .windows) {
        apk_exe.subsystem = .windows;
        apk_exe.root_module.addWin32ResourceFile(.{ .file = b.path("apk_editor/res/app.rc") });
        apk_exe.root_module.linkSystemLibrary("user32", .{});
        apk_exe.root_module.linkSystemLibrary("gdi32", .{});
        apk_exe.root_module.linkSystemLibrary("kernel32", .{});
        apk_exe.root_module.linkSystemLibrary("comdlg32", .{});
        apk_exe.root_module.linkSystemLibrary("shell32", .{});
        apk_exe.root_module.linkSystemLibrary("comctl32", .{});
        apk_exe.root_module.linkSystemLibrary("dwmapi", .{});
        apk_exe.root_module.linkSystemLibrary("uxtheme", .{});
        apk_exe.root_module.linkSystemLibrary("ole32", .{});
        apk_exe.root_module.linkSystemLibrary("shcore", .{});
        apk_exe.root_module.linkSystemLibrary("gdiplus", .{});
        apk_exe.root_module.link_libc = true;
        apk_exe.root_module.link_libcpp = true; // нужно для C++ (LZHAM)

        // ── LZMA SDK: базовый набор для LzmaUncompress ──
        apk_exe.root_module.addCSourceFiles(.{
            .files = &.{
                "apk_editor/libs/lzma/C/Alloc.c",
                "apk_editor/libs/lzma/C/CpuArch.c",
                "apk_editor/libs/lzma/C/LzFind.c",
                "apk_editor/libs/lzma/C/LzmaDec.c",
                "apk_editor/libs/lzma/C/LzmaEnc.c",
                "apk_editor/libs/lzma/C/LzmaLib.c",
            },
            .flags = &.{ "-O2", "-DZ7_ST" },
        });
        apk_exe.root_module.addIncludePath(b.path("apk_editor/libs/lzma/C"));

        // ── LZHAM: декомпрессор + C-API обёртка ──
        apk_exe.root_module.addCSourceFiles(.{
            .files = &.{
                "apk_editor/libs/lzham/lzhamdecomp/lzham_assert.cpp",
                "apk_editor/libs/lzham/lzhamdecomp/lzham_checksum.cpp",
                "apk_editor/libs/lzham/lzhamdecomp/lzham_huffman_codes.cpp",
                "apk_editor/libs/lzham/lzhamdecomp/lzham_lzdecomp.cpp",
                "apk_editor/libs/lzham/lzhamdecomp/lzham_lzdecompbase.cpp",
                "apk_editor/libs/lzham/lzhamdecomp/lzham_mem.cpp",
                "apk_editor/libs/lzham/lzhamdecomp/lzham_platform.cpp",
                "apk_editor/libs/lzham/lzhamdecomp/lzham_prefix_coding.cpp",
                "apk_editor/libs/lzham/lzhamdecomp/lzham_symbol_codec.cpp",
                "apk_editor/libs/lzham/lzhamdecomp/lzham_timer.cpp",
                "apk_editor/libs/lzham/lzhamdecomp/lzham_vector.cpp",
                "apk_editor/libs/lzham/lzhamlib/lzham_lib.cpp",
            },
            .flags = &.{ "-O2", "-fno-strict-aliasing", "-DLZHAM_STATIC_LIB" },
        });
        apk_exe.root_module.addIncludePath(b.path("apk_editor/libs/lzham/include"));
        apk_exe.root_module.addIncludePath(b.path("apk_editor/libs/lzham/lzhamdecomp"));
        apk_exe.root_module.addIncludePath(b.path("apk_editor/libs/lzham/lzhamlib"));

        // ── astc-encoder: только декодер (ASTC-текстуры SCTX) + C-обёртка ──
        apk_exe.root_module.addCSourceFiles(.{
            .files = &.{
                "apk_editor/src/native/astc_wrap.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_averages_and_directions.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_block_sizes.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_color_quantize.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_color_unquantize.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_compress_symbolic.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_compute_variance.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_decompress_symbolic.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_diagnostic_trace.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_entry.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_find_best_partitioning.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_ideal_endpoints_and_weights.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_image.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_integer_sequence.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_mathlib.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_mathlib_softfloat.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_partition_tables.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_percentile_tables.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_pick_best_endpoint_format.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_quantization.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_symbolic_physical.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_weight_align.cpp",
                "apk_editor/libs/astc-encoder/Source/astcenc_weight_quant_xfer_tables.cpp",
            },
            .flags = &.{ "-O2", "-std=c++17", "-DASTCENC_DECOMPRESS_ONLY=1" },
        });
        apk_exe.root_module.addIncludePath(b.path("apk_editor/libs/astc-encoder/Source"));
    }

    b.installArtifact(apk_exe);

    const apk_editor_step = b.step("apk-editor", "Build the APK Patch Editor GUI executable");
    const install_apk_editor = b.addInstallArtifact(apk_exe, .{});
    apk_editor_step.dependOn(&install_apk_editor.step);
}
