const std = @import("std");
const bsvz = @import("bsvz");
const harness = @import("support/go_reference_harness.zig");

const corpus_path = "../go-sdk/script/interpreter/data/script_tests.json";

const ExactRow = struct {
    row: usize,
};

const DynamicRow = struct {
    index: usize,
    input_amount: i64 = 0,
    unlocking_asm: []const u8,
    locking_asm: []const u8,
    flags_text: []const u8,
    expected_text: []const u8,
};

fn accessOrSkip(rel_path: []const u8) !void {
    std.fs.cwd().access(rel_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
}

fn containsToken(script_asm: []const u8, needle: []const u8) bool {
    var iter = std.mem.tokenizeScalar(u8, script_asm, ' ');
    while (iter.next()) |token| {
        if (std.mem.eql(u8, token, needle)) return true;
    }
    return false;
}

fn hasBlockedOpcodeTokens(unlocking_asm: []const u8, locking_asm: []const u8) bool {
    const blocked = [_][]const u8{
        "CHECKSIG",
        "CHECKSIGVERIFY",
        "CHECKMULTISIG",
        "CHECKMULTISIGVERIFY",
    };

    inline for (blocked) |token| {
        if (containsToken(unlocking_asm, token) or containsToken(locking_asm, token)) return true;
    }
    return false;
}

fn parseFlags(text: []const u8) ?bsvz.script.engine.ExecutionFlags {
    const has_post_genesis = std.mem.indexOf(u8, text, "UTXO_AFTER_GENESIS") != null;
    var flags = if (has_post_genesis)
        bsvz.script.engine.ExecutionFlags.postGenesisBsv()
    else
        bsvz.script.engine.ExecutionFlags.legacyReference();

    var parts = std.mem.splitScalar(u8, text, ',');
    while (parts.next()) |raw_part| {
        const part = std.mem.trim(u8, raw_part, " \t\r\n");
        if (part.len == 0) continue;
        if (std.mem.eql(u8, part, "P2SH")) continue;
        if (std.mem.eql(u8, part, "UTXO_AFTER_GENESIS")) continue;
        if (std.mem.eql(u8, part, "STRICTENC")) {
            flags.strict_encoding = true;
            continue;
        }
        if (std.mem.eql(u8, part, "DERSIG")) {
            flags.der_signatures = true;
            continue;
        }
        if (std.mem.eql(u8, part, "LOW_S")) {
            flags.low_s = true;
            continue;
        }
        if (std.mem.eql(u8, part, "NULLFAIL")) {
            flags.null_fail = true;
            continue;
        }
        if (std.mem.eql(u8, part, "NULLDUMMY")) {
            flags.null_dummy = true;
            continue;
        }
        if (std.mem.eql(u8, part, "SIGPUSHONLY")) {
            flags.sig_push_only = true;
            continue;
        }
        if (std.mem.eql(u8, part, "CLEANSTACK")) {
            flags.clean_stack = true;
            continue;
        }
        if (std.mem.eql(u8, part, "MINIMALDATA")) {
            flags.minimal_data = true;
            continue;
        }
        if (std.mem.eql(u8, part, "MINIMALIF")) {
            flags.minimal_if = true;
            continue;
        }
        if (std.mem.eql(u8, part, "DISCOURAGE_UPGRADABLE_NOPS")) {
            flags.discourage_upgradable_nops = true;
            continue;
        }
        if (std.mem.eql(u8, part, "CHECKLOCKTIMEVERIFY")) {
            flags.verify_check_locktime = true;
            continue;
        }
        if (std.mem.eql(u8, part, "CHECKSEQUENCEVERIFY")) {
            flags.verify_check_sequence = true;
            continue;
        }
        if (std.mem.eql(u8, part, "SIGHASH_FORKID")) {
            flags.enable_sighash_forkid = true;
            flags.verify_bip143_sighash = true;
            continue;
        }
        return null;
    }

    return flags;
}

fn parseExpected(text: []const u8) ?harness.Expectation {
    if (std.mem.eql(u8, text, "OK")) return .{ .success = true };
    if (std.mem.eql(u8, text, "EVAL_FALSE")) return .{ .success = false };
    if (std.mem.eql(u8, text, "BAD_OPCODE")) return .{ .err = error.UnknownOpcode };
    if (std.mem.eql(u8, text, "INVALID_STACK_OPERATION")) return .{ .err = error.StackUnderflow };
    if (std.mem.eql(u8, text, "INVALID_ALTSTACK_OPERATION")) return .{ .err = error.AltStackUnderflow };
    if (std.mem.eql(u8, text, "OP_RETURN")) return .{ .err = error.ReturnEncountered };
    if (std.mem.eql(u8, text, "MINIMALDATA")) return .{ .err = error.MinimalData };
    if (std.mem.eql(u8, text, "SCRIPTNUM_MINENCODE")) return .{ .err = error.MinimalData };
    if (std.mem.eql(u8, text, "MINIMALIF")) return .{ .err = error.MinimalIf };
    if (std.mem.eql(u8, text, "DISABLED_OPCODE")) return .{ .err = error.UnknownOpcode };
    if (std.mem.eql(u8, text, "SCRIPTNUM_OVERFLOW")) return .{ .err = error.NumberTooBig };
    if (std.mem.eql(u8, text, "OPERAND_SIZE")) return .{ .err = error.InvalidOperandSize };
    if (std.mem.eql(u8, text, "SIG_PUSHONLY")) return .{ .err = error.SigPushOnly };
    if (std.mem.eql(u8, text, "CLEANSTACK")) return .{ .err = error.CleanStack };
    if (std.mem.eql(u8, text, "DISCOURAGE_UPGRADABLE_NOPS")) return .{ .err = error.DiscourageUpgradableNops };
    if (std.mem.eql(u8, text, "PUSH_SIZE")) return .{ .err = error.ElementTooBig };
    if (std.mem.eql(u8, text, "SCRIPT_SIZE")) return .{ .err = error.ScriptTooBig };
    if (std.mem.eql(u8, text, "NEGATIVE_LOCKTIME")) return .{ .err = error.NegativeLockTime };
    if (std.mem.eql(u8, text, "UNSATISFIED_LOCKTIME")) return .{ .err = error.UnsatisfiedLockTime };
    if (std.mem.eql(u8, text, "UNBALANCED_CONDITIONAL")) return .{ .err = error.UnbalancedConditionals };
    if (std.mem.eql(u8, text, "SIG_DER")) return .{ .err = error.InvalidSignatureEncoding };
    if (std.mem.eql(u8, text, "PUBKEYTYPE")) return .{ .err = error.InvalidPublicKeyEncoding };
    if (std.mem.eql(u8, text, "SIG_HASHTYPE")) return .{ .err = error.InvalidSigHashType };
    if (std.mem.eql(u8, text, "ILLEGAL_FORKID")) return .{ .err = error.IllegalForkId };
    if (std.mem.eql(u8, text, "NULLFAIL")) return .{ .err = error.NullFail };
    if (std.mem.eql(u8, text, "SIG_HIGH_S")) return .{ .err = error.HighS };
    if (std.mem.eql(u8, text, "SIG_NULLDUMMY")) return .{ .err = error.NullDummy };
    if (std.mem.eql(u8, text, "VERIFY")) return .{ .success = false };
    if (std.mem.eql(u8, text, "EQUALVERIFY")) return .{ .success = false };
    if (std.mem.eql(u8, text, "NUMBER_SIZE")) return .{ .err = error.NumberTooBig };
    if (std.mem.eql(u8, text, "INVALID_NUMBER_RANGE")) return .{ .err = error.NegativeShift };
    if (std.mem.eql(u8, text, "STACK_SIZE")) return .{ .err = error.StackSizeLimitExceeded };
    return null;
}

fn loadDynamicRow(index: usize, value: std.json.Value) ?DynamicRow {
    if (value != .array) return null;
    const items = value.array.items;
    if (items.len < 4 or items.len > 6) return null;

    var item_offset: usize = 0;
    var input_amount: i64 = 0;
    if (items[0] == .array) {
        const amount_items = items[0].array.items;
        if (amount_items.len == 0 or amount_items[0] != .float) return null;
        input_amount = @intFromFloat(amount_items[0].float * 100_000_000.0);
        item_offset = 1;
    }

    if (items.len < item_offset + 4 or items.len > item_offset + 5) return null;
    if (items[item_offset] != .string or items[item_offset + 1] != .string or items[item_offset + 2] != .string or items[item_offset + 3] != .string) return null;

    const row = DynamicRow{
        .index = index,
        .input_amount = input_amount,
        .unlocking_asm = items[item_offset].string,
        .locking_asm = items[item_offset + 1].string,
        .flags_text = items[item_offset + 2].string,
        .expected_text = items[item_offset + 3].string,
    };

    if (index == 1051 or index == 756 or index == 761 or index == 803 or index == 831) return null;
    if (parseFlags(row.flags_text) == null) return null;
    if (parseExpected(row.expected_text) == null) return null;
    if (hasBlockedOpcodeTokens(row.unlocking_asm, row.locking_asm)) return null;

    return row;
}

fn runDynamicRow(allocator: std.mem.Allocator, row: DynamicRow) !void {
    const flags = parseFlags(row.flags_text).?;
    const expected = parseExpected(row.expected_text).?;
    const name = try std.fmt.allocPrint(allocator, "go exact corpus row {d}", .{row.index});
    defer allocator.free(name);

    try harness.runCase(allocator, .{
        .name = name,
        .unlocking_asm = row.unlocking_asm,
        .locking_asm = row.locking_asm,
        .flags = flags,
        .expected = expected,
        .enable_legacy_p2sh = std.mem.indexOf(u8, row.flags_text, "P2SH") != null and !flags.utxo_after_genesis,
        .output_value = row.input_amount,
    });
}

test "exact go corpus rows execute through bsvz" {
    const allocator = std.testing.allocator;
    try accessOrSkip(corpus_path);

    const file = try std.fs.cwd().readFileAlloc(allocator, corpus_path, 8 * 1024 * 1024);
    defer allocator.free(file);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, file, .{});
    defer parsed.deinit();

    if (parsed.value != .array) return error.InvalidEncoding;

    const rows = [_]ExactRow{
        .{ .row = 13 },
        .{ .row = 14 },
        .{ .row = 15 },
        .{ .row = 16 },
        .{ .row = 17 },
        .{ .row = 18 },
        .{ .row = 19 },
        .{ .row = 20 },
        .{ .row = 30 },
        .{ .row = 37 },
        .{ .row = 38 },
        .{ .row = 39 },
        .{ .row = 40 },
        .{ .row = 41 },
        .{ .row = 42 },
        .{ .row = 43 },
        .{ .row = 44 },
        .{ .row = 45 },
        .{ .row = 46 },
        .{ .row = 47 },
        .{ .row = 48 },
        .{ .row = 49 },
        .{ .row = 50 },
        .{ .row = 51 },
        .{ .row = 52 },
        .{ .row = 72 },
        .{ .row = 73 },
        .{ .row = 74 },
        .{ .row = 75 },
        .{ .row = 76 },
        .{ .row = 77 },
        .{ .row = 78 },
        .{ .row = 79 },
        .{ .row = 80 },
        .{ .row = 81 },
        .{ .row = 82 },
        .{ .row = 83 },
        .{ .row = 85 },
        .{ .row = 86 },
        .{ .row = 87 },
        .{ .row = 88 },
        .{ .row = 118 },
        .{ .row = 129 },
        .{ .row = 131 },
        .{ .row = 134 },
        .{ .row = 149 },
        .{ .row = 184 },
        .{ .row = 214 },
        .{ .row = 215 },
        .{ .row = 216 },
        .{ .row = 249 },
        .{ .row = 251 },
        .{ .row = 253 },
        .{ .row = 255 },
        .{ .row = 256 },
        .{ .row = 260 },
        .{ .row = 299 },
        .{ .row = 300 },
        .{ .row = 301 },
        .{ .row = 302 },
        .{ .row = 320 },
        .{ .row = 321 },
        .{ .row = 323 },
        .{ .row = 324 },
        .{ .row = 533 },
        .{ .row = 534 },
        .{ .row = 342 },
        .{ .row = 343 },
        .{ .row = 344 },
        .{ .row = 345 },
        .{ .row = 346 },
        .{ .row = 347 },
        .{ .row = 348 },
        .{ .row = 349 },
        .{ .row = 350 },
        .{ .row = 351 },
        .{ .row = 352 },
        .{ .row = 354 },
        .{ .row = 355 },
        .{ .row = 356 },
        .{ .row = 357 },
        .{ .row = 358 },
        .{ .row = 359 },
        .{ .row = 360 },
        .{ .row = 361 },
        .{ .row = 362 },
        .{ .row = 363 },
        .{ .row = 364 },
        .{ .row = 365 },
        .{ .row = 366 },
        .{ .row = 367 },
        .{ .row = 368 },
        .{ .row = 369 },
        .{ .row = 370 },
        .{ .row = 371 },
        .{ .row = 372 },
        .{ .row = 373 },
        .{ .row = 374 },
        .{ .row = 375 },
        .{ .row = 376 },
        .{ .row = 377 },
        .{ .row = 378 },
        .{ .row = 379 },
        .{ .row = 380 },
        .{ .row = 381 },
        .{ .row = 382 },
        .{ .row = 383 },
        .{ .row = 384 },
        .{ .row = 385 },
        .{ .row = 386 },
        .{ .row = 387 },
        .{ .row = 388 },
        .{ .row = 389 },
        .{ .row = 390 },
        .{ .row = 391 },
        .{ .row = 392 },
        .{ .row = 393 },
        .{ .row = 394 },
        .{ .row = 395 },
        .{ .row = 396 },
        .{ .row = 397 },
        .{ .row = 398 },
        .{ .row = 399 },
        .{ .row = 400 },
        .{ .row = 401 },
        .{ .row = 402 },
        .{ .row = 403 },
        .{ .row = 404 },
        .{ .row = 405 },
        .{ .row = 406 },
        .{ .row = 407 },
        .{ .row = 411 },
        .{ .row = 412 },
        .{ .row = 413 },
        .{ .row = 414 },
        .{ .row = 415 },
        .{ .row = 417 },
        .{ .row = 418 },
        .{ .row = 419 },
        .{ .row = 420 },
        .{ .row = 421 },
        .{ .row = 443 },
        .{ .row = 444 },
        .{ .row = 445 },
        .{ .row = 446 },
        .{ .row = 447 },
        .{ .row = 448 },
        .{ .row = 449 },
        .{ .row = 450 },
        .{ .row = 451 },
        .{ .row = 452 },
        .{ .row = 453 },
        .{ .row = 454 },
        .{ .row = 455 },
        .{ .row = 456 },
        .{ .row = 457 },
        .{ .row = 458 },
        .{ .row = 459 },
        .{ .row = 460 },
        .{ .row = 461 },
        .{ .row = 462 },
        .{ .row = 463 },
        .{ .row = 464 },
        .{ .row = 465 },
        .{ .row = 473 },
        .{ .row = 474 },
        .{ .row = 475 },
        .{ .row = 476 },
        .{ .row = 477 },
        .{ .row = 478 },
        .{ .row = 479 },
        .{ .row = 480 },
        .{ .row = 481 },
        .{ .row = 540 },
        .{ .row = 546 },
        .{ .row = 547 },
        .{ .row = 548 },
        .{ .row = 549 },
        .{ .row = 550 },
        .{ .row = 551 },
        .{ .row = 553 },
        .{ .row = 560 },
        .{ .row = 561 },
        .{ .row = 562 },
        .{ .row = 563 },
        .{ .row = 564 },
        .{ .row = 565 },
        .{ .row = 566 },
        .{ .row = 567 },
        .{ .row = 568 },
        .{ .row = 613 },
        .{ .row = 614 },
        .{ .row = 615 },
        .{ .row = 616 },
        .{ .row = 617 },
        .{ .row = 618 },
        .{ .row = 619 },
        .{ .row = 620 },
        .{ .row = 621 },
        .{ .row = 622 },
        .{ .row = 676 },
        .{ .row = 681 },
        .{ .row = 682 },
        .{ .row = 684 },
        .{ .row = 686 },
        .{ .row = 699 },
        .{ .row = 700 },
        .{ .row = 701 },
        .{ .row = 702 },
        .{ .row = 703 },
        .{ .row = 704 },
        .{ .row = 705 },
        .{ .row = 706 },
        .{ .row = 707 },
        .{ .row = 708 },
        .{ .row = 709 },
        .{ .row = 710 },
        .{ .row = 711 },
        .{ .row = 712 },
        .{ .row = 713 },
        .{ .row = 714 },
        .{ .row = 715 },
        .{ .row = 716 },
        .{ .row = 717 },
        .{ .row = 718 },
        .{ .row = 719 },
        .{ .row = 720 },
        .{ .row = 721 },
        .{ .row = 722 },
        .{ .row = 723 },
        .{ .row = 724 },
        .{ .row = 725 },
        .{ .row = 726 },
        .{ .row = 727 },
        .{ .row = 728 },
        .{ .row = 729 },
        .{ .row = 730 },
        .{ .row = 731 },
        .{ .row = 732 },
        .{ .row = 733 },
        .{ .row = 734 },
        .{ .row = 735 },
        .{ .row = 736 },
        .{ .row = 737 },
        .{ .row = 738 },
        .{ .row = 739 },
        .{ .row = 741 },
        .{ .row = 742 },
        .{ .row = 743 },
        .{ .row = 747 },
        .{ .row = 748 },
        .{ .row = 749 },
        .{ .row = 750 },
        .{ .row = 751 },
        .{ .row = 752 },
        .{ .row = 765 },
        .{ .row = 766 },
        .{ .row = 767 },
        .{ .row = 768 },
        .{ .row = 769 },
        .{ .row = 770 },
        .{ .row = 772 },
        .{ .row = 773 },
        .{ .row = 774 },
        .{ .row = 775 },
        .{ .row = 776 },
        .{ .row = 777 },
        .{ .row = 778 },
        .{ .row = 779 },
        .{ .row = 780 },
        .{ .row = 781 },
        .{ .row = 782 },
        .{ .row = 783 },
        .{ .row = 785 },
        .{ .row = 786 },
        .{ .row = 787 },
        .{ .row = 788 },
        .{ .row = 789 },
        .{ .row = 808 },
        .{ .row = 809 },
        .{ .row = 810 },
        .{ .row = 811 },
        .{ .row = 812 },
        .{ .row = 813 },
        .{ .row = 814 },
        .{ .row = 815 },
        .{ .row = 816 },
        .{ .row = 817 },
        .{ .row = 820 },
        .{ .row = 821 },
        .{ .row = 822 },
        .{ .row = 824 },
        .{ .row = 825 },
        .{ .row = 826 },
        .{ .row = 827 },
        .{ .row = 828 },
        .{ .row = 829 },
        .{ .row = 830 },
        .{ .row = 834 },
        .{ .row = 835 },
        .{ .row = 836 },
        .{ .row = 837 },
        .{ .row = 838 },
        .{ .row = 839 },
        .{ .row = 840 },
        .{ .row = 841 },
        .{ .row = 842 },
        .{ .row = 843 },
        .{ .row = 844 },
        .{ .row = 845 },
        .{ .row = 846 },
        .{ .row = 847 },
        .{ .row = 850 },
        .{ .row = 851 },
        .{ .row = 856 },
        .{ .row = 857 },
        .{ .row = 858 },
        .{ .row = 859 },
        .{ .row = 860 },
        .{ .row = 861 },
        .{ .row = 862 },
        .{ .row = 863 },
        .{ .row = 864 },
        .{ .row = 897 },
        .{ .row = 898 },
        .{ .row = 899 },
        .{ .row = 900 },
        .{ .row = 901 },
        .{ .row = 902 },
        .{ .row = 903 },
        .{ .row = 904 },
        .{ .row = 905 },
        .{ .row = 906 },
        .{ .row = 907 },
        .{ .row = 908 },
        .{ .row = 909 },
        .{ .row = 910 },
        .{ .row = 911 },
        .{ .row = 912 },
        .{ .row = 913 },
        .{ .row = 914 },
        .{ .row = 915 },
        .{ .row = 917 },
        .{ .row = 918 },
        .{ .row = 919 },
        .{ .row = 920 },
        .{ .row = 921 },
        .{ .row = 922 },
        .{ .row = 923 },
        .{ .row = 924 },
        .{ .row = 925 },
        .{ .row = 926 },
        .{ .row = 927 },
        .{ .row = 928 },
        .{ .row = 929 },
        .{ .row = 930 },
        .{ .row = 931 },
        .{ .row = 932 },
        .{ .row = 933 },
        .{ .row = 934 },
        .{ .row = 935 },
        .{ .row = 938 },
        .{ .row = 939 },
        .{ .row = 946 },
        .{ .row = 947 },
        .{ .row = 948 },
        .{ .row = 949 },
        .{ .row = 950 },
        .{ .row = 951 },
        .{ .row = 952 },
        .{ .row = 953 },
        .{ .row = 954 },
        .{ .row = 955 },
        .{ .row = 956 },
        .{ .row = 957 },
        .{ .row = 958 },
        .{ .row = 959 },
        .{ .row = 960 },
        .{ .row = 961 },
        .{ .row = 962 },
        .{ .row = 963 },
        .{ .row = 964 },
        .{ .row = 965 },
        .{ .row = 966 },
        .{ .row = 1037 },
        .{ .row = 1038 },
        .{ .row = 1040 },
        .{ .row = 1041 },
        .{ .row = 1042 },
        .{ .row = 1050 },
        .{ .row = 1043 },
        .{ .row = 1053 },
        .{ .row = 1054 },
        .{ .row = 1055 },
        .{ .row = 1056 },
        .{ .row = 1057 },
        .{ .row = 1058 },
        .{ .row = 1059 },
        .{ .row = 1060 },
        .{ .row = 1061 },
        .{ .row = 1062 },
        .{ .row = 1063 },
        .{ .row = 1064 },
        .{ .row = 1065 },
        .{ .row = 1066 },
        .{ .row = 1067 },
        .{ .row = 1068 },
        .{ .row = 1069 },
        .{ .row = 1070 },
        .{ .row = 1071 },
        .{ .row = 1072 },
        .{ .row = 1073 },
        .{ .row = 1074 },
        .{ .row = 1075 },
        .{ .row = 1076 },
        .{ .row = 1077 },
        .{ .row = 1078 },
        .{ .row = 1079 },
        .{ .row = 1080 },
        .{ .row = 1081 },
        .{ .row = 1082 },
        .{ .row = 1083 },
        .{ .row = 1084 },
        .{ .row = 1085 },
        .{ .row = 1086 },
        .{ .row = 1087 },
        .{ .row = 1088 },
        .{ .row = 1089 },
        .{ .row = 1090 },
        .{ .row = 1091 },
        .{ .row = 1092 },
        .{ .row = 1093 },
        .{ .row = 1094 },
        .{ .row = 1095 },
        .{ .row = 1096 },
        .{ .row = 1097 },
        .{ .row = 1098 },
        .{ .row = 1099 },
        .{ .row = 1100 },
        .{ .row = 1101 },
        .{ .row = 1102 },
        .{ .row = 1103 },
        .{ .row = 1104 },
        .{ .row = 1105 },
        .{ .row = 1106 },
        .{ .row = 1107 },
        .{ .row = 1108 },
        .{ .row = 1109 },
        .{ .row = 1110 },
        .{ .row = 1111 },
        .{ .row = 1112 },
        .{ .row = 1113 },
        .{ .row = 1114 },
        .{ .row = 1115 },
        .{ .row = 1116 },
        .{ .row = 1117 },
        .{ .row = 1118 },
        .{ .row = 1119 },
        .{ .row = 1120 },
        .{ .row = 1121 },
        .{ .row = 1122 },
        .{ .row = 1123 },
        .{ .row = 1129 },
        .{ .row = 1130 },
        .{ .row = 1131 },
        .{ .row = 1132 },
        .{ .row = 1135 },
        .{ .row = 1136 },
        .{ .row = 1137 },
        .{ .row = 1138 },
        .{ .row = 1139 },
        .{ .row = 1140 },
        .{ .row = 1141 },
        .{ .row = 1142 },
        .{ .row = 1143 },
        .{ .row = 1144 },
        .{ .row = 1145 },
        .{ .row = 1146 },
        .{ .row = 1147 },
        .{ .row = 1148 },
        .{ .row = 1149 },
        .{ .row = 1150 },
        .{ .row = 1151 },
        .{ .row = 1152 },
        .{ .row = 1153 },
        .{ .row = 1154 },
        .{ .row = 1155 },
        .{ .row = 1156 },
        .{ .row = 1157 },
        .{ .row = 1161 },
        .{ .row = 1162 },
        .{ .row = 1163 },
        .{ .row = 1164 },
        .{ .row = 1165 },
        .{ .row = 1166 },
        .{ .row = 1167 },
        .{ .row = 1168 },
        .{ .row = 1169 },
        .{ .row = 1174 },
        .{ .row = 1175 },
        .{ .row = 1176 },
        .{ .row = 1177 },
        .{ .row = 1178 },
        .{ .row = 1179 },
        .{ .row = 1180 },
        .{ .row = 1181 },
        .{ .row = 1182 },
        .{ .row = 1183 },
        .{ .row = 1184 },
        .{ .row = 1185 },
        .{ .row = 1186 },
        .{ .row = 1187 },
        .{ .row = 1188 },
        .{ .row = 1189 },
        .{ .row = 1190 },
        .{ .row = 1191 },
        .{ .row = 1192 },
        .{ .row = 1193 },
        .{ .row = 1194 },
        .{ .row = 1195 },
        .{ .row = 1196 },
        .{ .row = 1197 },
        .{ .row = 1198 },
        .{ .row = 1199 },
        .{ .row = 1200 },
        .{ .row = 1201 },
        .{ .row = 1202 },
        .{ .row = 1203 },
        .{ .row = 1204 },
        .{ .row = 1221 },
        .{ .row = 1222 },
        .{ .row = 1223 },
        .{ .row = 1224 },
        .{ .row = 1225 },
        .{ .row = 1230 },
        .{ .row = 1231 },
        .{ .row = 1232 },
        .{ .row = 1233 },
        .{ .row = 1234 },
        .{ .row = 1235 },
        .{ .row = 1236 },
        .{ .row = 1237 },
        .{ .row = 1239 },
        .{ .row = 1240 },
        .{ .row = 1241 },
        .{ .row = 1242 },
        .{ .row = 1243 },
        .{ .row = 1244 },
        .{ .row = 1326 },
        .{ .row = 1327 },
        .{ .row = 1328 },
        .{ .row = 1329 },
        .{ .row = 1330 },
        .{ .row = 1333 },
        .{ .row = 1334 },
        .{ .row = 1389 },
        .{ .row = 1390 },
        .{ .row = 1399 },
        .{ .row = 1401 },
        .{ .row = 1403 },
        .{ .row = 1404 },
        .{ .row = 1408 },
        .{ .row = 1409 },
        .{ .row = 1410 },
        .{ .row = 1439 },
        .{ .row = 1440 },
        .{ .row = 1441 },
        .{ .row = 1442 },
        .{ .row = 1443 },
        .{ .row = 1445 },
        .{ .row = 1446 },
        .{ .row = 1447 },
        .{ .row = 1448 },
        .{ .row = 1449 },
        .{ .row = 1450 },
        .{ .row = 1451 },
        .{ .row = 1452 },
        .{ .row = 1453 },
        .{ .row = 1454 },
        .{ .row = 1455 },
        .{ .row = 1456 },
        .{ .row = 1457 },
        .{ .row = 1458 },
        .{ .row = 1459 },
        .{ .row = 1460 },
        .{ .row = 1461 },
        .{ .row = 1462 },
        .{ .row = 1463 },
        .{ .row = 1464 },
        .{ .row = 1466 },
        .{ .row = 1467 },
        .{ .row = 1468 },
        .{ .row = 1469 },
        .{ .row = 1470 },
        .{ .row = 1471 },
        .{ .row = 1472 },
        .{ .row = 1473 },
        .{ .row = 1474 },
        .{ .row = 1475 },
        .{ .row = 1476 },
        .{ .row = 1477 },
        .{ .row = 1478 },
        .{ .row = 1479 },
        .{ .row = 1480 },
        .{ .row = 1481 },
        .{ .row = 1482 },
        .{ .row = 1483 },
        .{ .row = 1421 },
        .{ .row = 1422 },
        .{ .row = 1424 },
        .{ .row = 1425 },
        .{ .row = 84 },
        .{ .row = 211 },
        .{ .row = 212 },
        .{ .row = 213 },
        .{ .row = 218 },
        .{ .row = 219 },
        .{ .row = 220 },
        .{ .row = 221 },
        .{ .row = 278 },
        .{ .row = 279 },
        .{ .row = 280 },
        .{ .row = 1028 },
        .{ .row = 1029 },
        .{ .row = 1030 },
        .{ .row = 1031 },
        .{ .row = 1032 },
        .{ .row = 1033 },
        .{ .row = 1034 },
        .{ .row = 1035 },
        .{ .row = 1036 },
        .{ .row = 191 },
        .{ .row = 192 },
        .{ .row = 194 },
        .{ .row = 196 },
        .{ .row = 217 },
        .{ .row = 223 },
        .{ .row = 226 },
        .{ .row = 232 },
        .{ .row = 236 },
        .{ .row = 244 },
        .{ .row = 248 },
        .{ .row = 250 },
        .{ .row = 252 },
        .{ .row = 254 },
        .{ .row = 257 },
        .{ .row = 258 },
        .{ .row = 259 },
        .{ .row = 261 },
        .{ .row = 262 },
        .{ .row = 263 },
        .{ .row = 322 },
        .{ .row = 637 },
        .{ .row = 641 },
        .{ .row = 944 },
        .{ .row = 740 },
        .{ .row = 771 },
        .{ .row = 818 },
        .{ .row = 1133 },
        .{ .row = 1134 },
    };

    for (rows) |row_ref| {
        const value = parsed.value.array.items[row_ref.row];
        const row = loadDynamicRow(row_ref.row, value) orelse {
            std.debug.print("go exact corpus row {} no longer qualifies for exact import\n", .{row_ref.row});
            return error.InvalidEncoding;
        };
        runDynamicRow(allocator, row) catch |err| {
            std.debug.print(
                "go exact corpus row {} failed\n  unlocking: {s}\n  locking: {s}\n  flags: {s}\n  expected: {s}\n",
                .{ row.index, row.unlocking_asm, row.locking_asm, row.flags_text, row.expected_text },
            );
            return err;
        };
    }
}
