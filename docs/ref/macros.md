# Macros

This document provides a complete reference for all macros available in Revizor.

!!! note "Related Documentation"
    This document is intended as a reference; if you're looking for a practical guide on how to use the `macros`, please refer to [How-To: Use Macros](../howto/use-macros.md).

## Overview

Macros are special pseudo-instructions in assembly test cases that appear as labels with the `.macro` prefix. They are dynamically expanded into actual implementations during execution by the model and executor. Macros enable complex operations like domain transitions, measurement control, and random code generation within test cases.

Macros accept up to four static arguments. Arguments are strictly static (either a constant integer or a string); dynamic values (registers, memory addresses) are not supported.

=== "Syntax"

    ```assembly
    .macro.<macro_name>.<argument1>.<argument2>.<argument3>.<argument4>:
    ```

=== "Example"

    ```assembly
    ; Macro to switch execution to
    ; a function called `main` that belongs to the actor `actor_2`
    .macro.switch.user.function_user_0:
    ```

## Measurement Macros

Control the start and end of hardware and contract trace collection.

#### <a name="measurement_start"></a> `measurement_start`

:   Begins hardware and contract trace collection. Instructions before this macro are executed but not included in the contract/hardware traces.

    === "Syntax"
        ```assembly
        .macro.measurement_start:

        ; alternative
        .macro.measurement_start.<label>:
        ```

    === "Arguments"
        1. `label` (optional): Unique identifier if the macro is used multiple times


#### <a name="measurement_end"></a> `measurement_end`

:   Ends hardware and contract trace collection. Instructions after this macro are executed but not included in the contract/hardware traces.

    === "Syntax"
        ```assembly
        .macro.measurement_end:

        ; alternative
        .macro.measurement_end.<label>:
        ```

    === "Arguments"
        1. `label` (optional): Unique identifier if the macro is used multiple times


## Transition Macros

Switch between different actors and privilege levels, including kernel-user and host-guest transitions.

#### <a name="set_h2g_target"></a> `set_h2g_target`

:   Sets the VM entry point for host-to-guest transitions.

    === "Syntax"
        ```assembly
        .macro.set_h2g_target.<actor_name>.<function_name>:
        ```

    === "Arguments"
        - `actor_name`: Target guest actor identifier
        - `function_name`: Entry point function in guest actor

#### <a name="set_g2h_target"></a> `set_g2h_target`

:   Sets the VM exit point for guest-to-host transitions.

    === "Syntax"
        ```assembly
        .macro.set_g2h_target.<actor_name>.<function_name>:
        ```

    === "Arguments"
        - `actor_name`: Target host actor identifier
        - `function_name`: Landing point function in host actor

#### <a name="switch_h2g"></a> `switch_h2g`

:   Performs host-to-guest transition (VM entry). The entry and exit point must be set beforehand using `set_h2g_target` and `set_g2h_target` macros.

    === "Syntax"
        ```assembly
        .macro.switch_h2g.<actor_name>.<label>:
        ```

    === "Arguments"
        - `actor_name`: Target guest actor identifier
        - `label` (optional): Unique identifier if the macro is used multiple times


#### <a name="landing_h2g"></a> `landing_h2g`

:   Marks the guest landing point after host-to-guest transition. This macro works together with `switch_h2g` to ensure complete restoration of the execution context.

    === "Syntax"
        ```assembly
        .macro.landing_h2g.<label>:
        ```

    === "Arguments"
        - `label` (optional): Unique identifier if the macro is used multiple times


#### <a name="switch_g2h"></a> `switch_g2h`

:   Performs guest-to-host transition (VM exit). The entry and exit point must be set beforehand using `set_h2g_target` and `set_g2h_target` macros.

    === "Syntax"
        ```assembly
        .macro.switch_g2h.<actor_name>.<label>:
        ```

    === "Arguments"
        - `actor_name`: Target host actor identifier
        - `label` (optional): Unique identifier if the macro is used multiple times


#### <a name="landing_g2h"></a> `landing_g2h`

:   Marks the host landing point after guest-to-host transition. This macro works together with `switch_g2h` to ensure complete restoration of the execution context.

    === "Syntax"
        ```assembly
        .macro.landing_g2h.<label>:
        ```

    === "Arguments"
        - `label` (optional): Unique identifier if the macro is used multiple times


#### <a name="set_k2u_target"></a> `set_k2u_target`

:   Sets the user mode entry point for kernel-to-user transitions.

    === "Syntax"
        ```assembly
        .macro.set_k2u_target.<actor_name>.<function_name>:
        ```

    === "Arguments"
        - `actor_name`: Target user-mode actor identifier
        - `function_name`: Entry point function in user actor


#### <a name="set_u2k_target"></a> `set_u2k_target`

:   Sets the kernel mode entry point for user-to-kernel transitions.

    === "Syntax"
        ```assembly
        .macro.set_u2k_target.<actor_name>.<function_name>:
        ```

    === "Arguments"
        - `actor_name`: Target kernel-mode actor identifier
        - `function_name`: Entry point function in kernel actor


#### <a name="switch_k2u"></a> `switch_k2u`

:   Performs kernel-to-user transition (privilege level drop). The entry and exit point must be set beforehand using `set_k2u_target` and `set_u2k_target` macros.

    === "Syntax"
        ```assembly
        .macro.switch_k2u.<actor_name>.<label>:
        ```

    === "Arguments"
        - `actor_name`: Target user actor identifier
        - `label` (optional): Unique identifier if the macro is used multiple times


#### <a name="switch_u2k"></a> `switch_u2k`

:   Performs user-to-kernel transition (privilege level escalation). The entry and exit point must be set beforehand using `set_k2u_target` and `set_u2k_target` macros.

    === "Syntax"
        ```assembly
        .macro.switch_u2k.<actor_name>.<label>:
        ```

    === "Arguments"
        - `actor_name`: Target kernel actor identifier
        - `label` (optional): Unique identifier if the macro is used multiple times


#### <a name="landing_k2u"></a> `landing_k2u`

:   Marks the user-mode landing point after kernel-to-user transition.  This macro works together with `switch_k2u` to ensure complete restoration of the execution context.

    === "Syntax"
        ```assembly
        .macro.landing_k2u.<label>:
        ```

    === "Arguments"
        - `label` (optional): Unique identifier if the macro is used multiple times


#### <a name="landing_u2k"></a> `landing_u2k`

:   Marks the kernel-mode landing point after user-to-kernel transition.  This macro works together with `switch_u2k` to ensure complete restoration of the execution context.

    === "Syntax"
        ```assembly
        .macro.landing_u2k.<label>:
        ```

    === "Arguments"
        - `label` (optional): Unique identifier if the macro is used multiple times

## Fault Handling Macros

Define exception and interrupt handlers within test cases.

#### <a name="fault_handler"></a> `fault_handler`

:   Specifies the control flow target for exceptions and interrupts. When an exception occurs, control transfers to this location. If not defined, the executor uses a default handler that jumps to the test case exit point.

    === "Syntax"
        ```assembly
        .macro.fault_handler:
        ```

    === "Arguments"
        - None


## Environment Configuration Macros

Change the execution environment from within a test case.

#### <a name="set_data_permissions"></a> set_data_permissions

:   Configures data permission on the faulty page of the current actor by modifying the page table entry (PTE) permissions.

    === "Syntax"
        ```assembly
        .macro.set_data_permissions.<set_mask>.<clear_mask>:
        ```
    === "Arguments"
        - `set_mask`: 16-bit bitmask specifying which permission bits to set (ORed with the faulty page's PTE)
        - `clear_mask`: 16-bit bitmask specifying which permission bits to clear (ANDed with the faulty page's PTE)


## Generation Macros

Define automatically-generated points within a template. Available only in the [Template Fuzzing Mode](modes.md#tfuzz)

In contrast to the rest of the macros, generation macros are used by the generator instead of the executor or model. By the point the executor/model run the test case, these macros are expected to have been already expanded into actual code.

#### <a name="random_instructions"></a> `random_instructions`

:   Generates N random instructions during template expansion. Used in template fuzzing mode to insert randomized code sequences.

    === "Syntax"
        ```assembly
        .macro.random_instructions.<num_instructions>.<avg_mem_accesses>.<label>:
        ```

    === "Arguments"
        - `num_instructions`: Number of random instructions to generate
        - `avg_mem_accesses`: Average number of memory accesses. Average means that when a large-enough number of test cases are generated, the mean number of memory accesses per expansion of this macro will approximate this value.
        - `label` (optional): Unique identifier if the macro is used multiple times

---

## What's Next?

- [How to Use Macros](../howto/use-macros.md) - Detailed usage guide and implementation details
- [How to Use Templates](../howto/use-templates.md) - Template-based testing
- [Actors](../topics/actors.md) - Multi-domain testing concepts

**Examples:**

- [demo/tsa-l1d/template.asm](https://github.com/microsoft/side-channel-fuzzer/tree/main/demo/tsa-l1d/template.asm) - TSA-L1D attack template with actor transitions
- [demo/tsa-sq/template.asm](https://github.com/microsoft/side-channel-fuzzer/tree/main/demo/tsa-sq/template.asm) - TSA-SQ attack template with actor transitions
