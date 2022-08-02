# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

import lldb
import sys
from lldb_sgx_plugin import *

def lldb_eval(expr):
    return lldb.debugger.GetSelectedTarget().EvaluateExpression(expr)

def lldb_expr(expr):
    lldb.debugger.HandleCommand(f"expr {expr}")

def lldb_read_string(address):
    process = lldb.debugger.GetSelectedTarget().GetProcess()
    return process.ReadCStringFromMemory(address, 32, lldb.SBError())

def lldb_quit():
    process = lldb.debugger.GetSelectedTarget().GetProcess()
    process.Destroy()

def bp_main(frame, bp_loc, dict):
    print("** Hit breakpoint in main")
    argv_1 = lldb_eval("argv[1]")
    enclave = lldb_read_string(int(str(argv_1.value), 16))
    print(f"** enclave = {enclave}")
    return False

def bp_enc_c_17(frame, bp_loc, dict):
    print("** Hit breakpoint in enclave")
    a = int(lldb_eval("a").value)
    b = int(lldb_eval("b").value)
    print(f"** a = {a}, b = {b}")

    if a != 5:
        print("** Error: a != 5")
        lldb_quit()

    if b != 6:
        print("** Error: b != 6")
        lldb_quit()

    return False

def bp_enc_c_26(frame, bp_loc, dict):
    c = int(lldb_eval("c").value)
    print("** c = %d" % c)
    if c != 11:
        print("** Error: c != 11")
        lldb_quit()

    print("Setting c")
    lldb.debugger.HandleCommand("expr c = 100")
    return False

def bp_enc_c_30(frame, bp_loc, dict):
    c = int(lldb_eval("c").value)
    print("** c = %d" % c)
    if c != 100:
        print("** Error: c != 100")
        lldb_quit()

    # Call a function defined within the enclave when vDSO
    # is not enabled (in-encave SIGSEGV will be suppressed).
    is_vdso_enabled = bool(lldb_eval("oe_sgx_is_vdso_enabled").value)
    if not is_vdso_enabled:
        # This doesn't work
        lldb.debugger.HandleCommand("expr square(1)")

    lldb.debugger.HandleCommand("expr c = 10000, g_square_called=1")
    return False

def bp_assert_debugger_binary_contract_host_side(frame, bp_loc, dict):
    print("Serializing debugger contract on host side....")

    # oe_debug_enclave_t
    lldb_expr(f"ENCLAVE_OFFSETOF_MAGIC = {str(oe_debug_enclave_t.OFFSETOF_MAGIC)}")
    lldb_expr(f"ENCLAVE_SIZEOF_MAGIC = {str(oe_debug_enclave_t.SIZEOF_MAGIC)}")
    lldb_expr(f"ENCLAVE_MAGIC_VALUE = {str(oe_debug_enclave_t.MAGIC_VALUE)}")

    lldb_expr(
        f"ENCLAVE_OFFSETOF_VERSION = {str(oe_debug_enclave_t.OFFSETOF_VERSION)}"
    )

    lldb_expr(f"ENCLAVE_SIZEOF_VERSION = {str(oe_debug_enclave_t.SIZEOF_VERSION)}")

    lldb_expr(f"ENCLAVE_OFFSETOF_NEXT = {str(oe_debug_enclave_t.OFFSETOF_NEXT)}")
    lldb_expr(f"ENCLAVE_SIZEOF_NEXT = {str(oe_debug_enclave_t.SIZEOF_NEXT)}")

    lldb_expr(f"ENCLAVE_OFFSETOF_PATH = {str(oe_debug_enclave_t.OFFSETOF_PATH)}")
    lldb_expr(f"ENCLAVE_SIZEOF_PATH = {str(oe_debug_enclave_t.SIZEOF_PATH)}")

    lldb_expr(
        f"ENCLAVE_OFFSETOF_PATH_LENGTH = {str(oe_debug_enclave_t.OFFSETOF_PATH_LENGTH)}"
    )

    lldb_expr(
        f"ENCLAVE_SIZEOF_PATH_LENGTH = {str(oe_debug_enclave_t.SIZEOF_PATH_LENGTH)}"
    )


    lldb_expr(
        f"ENCLAVE_OFFSETOF_BASE_ADDRESS = {str(oe_debug_enclave_t.OFFSETOF_BASE_ADDRESS)}"
    )

    lldb_expr(
        f"ENCLAVE_SIZEOF_BASE_ADDRESS = {str(oe_debug_enclave_t.SIZEOF_BASE_ADDRESS)}"
    )


    lldb_expr(f"ENCLAVE_OFFSETOF_SIZE = {str(oe_debug_enclave_t.OFFSETOF_SIZE)}")
    lldb_expr(f"ENCLAVE_SIZEOF_SIZE = {str(oe_debug_enclave_t.SIZEOF_SIZE)}")

    lldb_expr(
        f"ENCLAVE_OFFSETOF_TCS_ARRAY = {str(oe_debug_enclave_t.OFFSETOF_TCS_ARRAY)}"
    )

    lldb_expr(
        f"ENCLAVE_SIZEOF_TCS_ARRAY = {str(oe_debug_enclave_t.SIZEOF_TCS_ARRAY)}"
    )


    lldb_expr(
        f"ENCLAVE_OFFSETOF_TCS_COUNT = {str(oe_debug_enclave_t.OFFSETOF_TCS_COUNT)}"
    )

    lldb_expr(
        f"ENCLAVE_SIZEOF_TCS_COUNT = {str(oe_debug_enclave_t.SIZEOF_TCS_COUNT)}"
    )


    lldb_expr(f"ENCLAVE_OFFSETOF_FLAGS = {str(oe_debug_enclave_t.OFFSETOF_FLAGS)}")
    lldb_expr(f"ENCLAVE_SIZEOF_FLAGS = {str(oe_debug_enclave_t.SIZEOF_FLAGS)}")
    lldb_expr(f"ENCLAVE_MASK_DEBUG = {str(oe_debug_enclave_t.MASK_DEBUG)}")
    lldb_expr(f"ENCLAVE_MASK_SIMULATE = {str(oe_debug_enclave_t.MASK_SIMULATE)}")

    lldb_expr(
        f"ENCLAVE_OFFSETOF_MODULES = {str(oe_debug_enclave_t.OFFSETOF_MODULES)}"
    )

    lldb_expr(f"ENCLAVE_SIZEOF_MODULES = {str(oe_debug_enclave_t.SIZEOF_MODULES)}")


    # oe_debug_module_t
    lldb_expr(f"MODULE_OFFSETOF_MAGIC = {str(oe_debug_module_t.OFFSETOF_MAGIC)}")
    lldb_expr(f"MODULE_SIZEOF_MAGIC = {str(oe_debug_module_t.SIZEOF_MAGIC)}")
    lldb_expr(f"MODULE_MAGIC_VALUE = {str(oe_debug_module_t.MAGIC_VALUE)}")

    lldb_expr(
        f"MODULE_OFFSETOF_VERSION = {str(oe_debug_module_t.OFFSETOF_VERSION)}"
    )

    lldb_expr(f"MODULE_SIZEOF_VERSION = {str(oe_debug_module_t.SIZEOF_VERSION)}")

    lldb_expr(f"MODULE_OFFSETOF_NEXT = {str(oe_debug_module_t.OFFSETOF_NEXT)}")
    lldb_expr(f"MODULE_SIZEOF_NEXT = {str(oe_debug_module_t.SIZEOF_NEXT)}")

    lldb_expr(f"MODULE_OFFSETOF_PATH = {str(oe_debug_module_t.OFFSETOF_PATH)}")
    lldb_expr(f"MODULE_SIZEOF_PATH = {str(oe_debug_module_t.SIZEOF_PATH)}")

    lldb_expr(
        f"MODULE_OFFSETOF_PATH_LENGTH = {str(oe_debug_module_t.OFFSETOF_PATH_LENGTH)}"
    )

    lldb_expr(
        f"MODULE_SIZEOF_PATH_LENGTH = {str(oe_debug_module_t.SIZEOF_PATH_LENGTH)}"
    )


    lldb_expr(
        f"MODULE_OFFSETOF_BASE_ADDRESS = {str(oe_debug_module_t.OFFSETOF_BASE_ADDRESS)}"
    )

    lldb_expr(
        f"MODULE_SIZEOF_BASE_ADDRESS = {str(oe_debug_module_t.SIZEOF_BASE_ADDRESS)}"
    )


    lldb_expr(f"MODULE_OFFSETOF_SIZE = {str(oe_debug_module_t.OFFSETOF_SIZE)}")
    lldb_expr(f"MODULE_SIZEOF_SIZE = {str(oe_debug_module_t.SIZEOF_SIZE)}")

    print("Debugger contract serialized on host side.")
    return False

def bp_assert_debugger_binary_contract_enclave_side(frame, bp_loc, dict):
    print("Serializing debugger contract on enclave side....")

    lldb_expr(f"TCS_GSBASE_OFFSET = {str(TCS_GSBASE_OFFSET)}")

    print("Debugger contract serialized on enclave side.")
    return False

def bp_host_c_84(frame, bp_loc, dict):
    print("\n\n\nWalking ocall stack....\n\n")

    # Read magic value
    magic_value = lldb_eval("magic_value")
    print(f"magic_value = {magic_value.value}")

    # Set the magic variable in host_function.
    lldb_expr(f"host_function_magic={magic_value.value}")

    # We expect at most 50 frames while walking the stack. Additionally a finite
    # iteration limit guarantees that the test will terminate quickly even if
    # the debugger is not able to walk the stack correctly.
    for _ in range(50):
        print(frame.name)
        if frame.name == "enclave_function":
            frame.EvaluateExpression(f"enc_magic = {magic_value.value}")
            break
        frame = frame.parent

    # Continue walking the stack until main is reached.
    # This asserts ecall stack stitching.
    print("\n\n\nWalking ecall stack...\n\n")
    for _ in range(50):
        print(frame.name)
        if frame.name == "main":
            frame.EvaluateExpression(f"main_magic = {magic_value.value}")
            break
        frame = frame.parent

    print("\n\nStack stitching successfully validated\n\n")
    return False

def run_test():
    lldb.debugger.SetAsync(False)
    target = lldb.debugger.GetSelectedTarget()

    bp = target.BreakpointCreateByName("main")
    bp.SetScriptCallbackFunction('commands.bp_main')

    bp = target.BreakpointCreateByLocation("enc.c", 17)
    bp.SetScriptCallbackFunction('commands.bp_enc_c_17')

    bp = target.BreakpointCreateByLocation("enc.c", 26)
    bp.SetScriptCallbackFunction('commands.bp_enc_c_26')

    bp = target.BreakpointCreateByLocation("enc.c", 30)
    bp.SetScriptCallbackFunction('commands.bp_enc_c_30')

    bp = target.BreakpointCreateByName("assert_debugger_binary_contract_host_side")
    bp.SetScriptCallbackFunction('commands.bp_assert_debugger_binary_contract_host_side')

    bp = target.BreakpointCreateByName("assert_debugger_binary_contract_enclave_side")
    bp.SetScriptCallbackFunction('commands.bp_assert_debugger_binary_contract_enclave_side')

    bp = target.BreakpointCreateByLocation("host.c", 84)
    bp.SetScriptCallbackFunction('commands.bp_host_c_84')

    # The `personality` syscall is used by lldb to turn off ASLR.
    # This syscall may not be permitted within containers.
    # Therefore, turn off disable-aslr.
    lldb.debugger.HandleCommand("settings set target.disable-aslr false")
    lldb.debugger.HandleCommand("run")
    retval = lldb.debugger.GetSelectedTarget().GetProcess().exit_state
    if int(retval) == 0:
        print("oelldb test passed")
    else:
        print("oelldb test failed")

def __lldb_init_module(debugger, dict):
    run_test()
