# System monitor
Part of my practice in kernel-mode programming which I'm learning from <i>Windows Kernel Programming, Pavel Yosifuvich, 2020, chapter 8</i>,
I've created project used to monitor activities in the system level, such as:
* Process creation
* Process termination
* Thread creation
* Thread termination
* Image load
---

## How it works
I've created kernel-mode driver that register callback to be fired whenever one of the above mentioned event happens,
using the following kernel-function:

```C++
NTSTATUS PsSetCreateProcessNotifyRoutineEx(
  PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
  BOOLEAN                           Remove
);
```

```C++
NTSTATUS PsSetCreateThreadNotifyRoutine(
  PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
);
```

```C++
NTSTATUS PsSetLoadImageNotifyRoutine(
  PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
);
```
---

## Consuming events
TODO

---

## Common issues
#### Access Denied
When creating the driver service and starting it you can get Access-Denied error.<br>
This happing because the compiled driver didn't linked with with /integritycheck flag. <br>
To solve this add the flag to your driver project as follows:<br>
Project Properties -> Linker -> Command Line -> Additional Options -> type: <code>/integritycheck</code>

#### VCRUNTIME missing
When using the client application to read data from the Kernel-Driver you can get VCRUNTIMEXX.dll missing.<br>
This happen because of the required DLLs for executable file.<br>
To solve this change the compiler options as follows:<br>
Project Properties -> C/C++ -> Code Generation -> Runtime Library -> <code>Multi-threaded DLL(/MD)</code>


---

## ToDo
- [ ] Add user-mode application to consume events
- [ ] Create Service - start routine, stop routine
- [ ] Create launch routine: load the driver, start consuming events, add events to log file
- [ ] Read limit value for linked-list size from Driver's registry key
- [ ] Add to PsSetCreateProcessNotifyRoutineEx ImageFileName and ParentProcessId data
- [ ] Add caching to process and thread data
- [ ] Change application-to-driver communication from pooling to better method.
---

## Useful links
* Pavel Yosifuvich book - https://leanpub.com/windowskernelprogramming
* More about kernel callbacks - https://www.codemachine.com/article_kernel_callback_functions.html
* Tutorial from MSDN about Linked-Lists - https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/singly-and-doubly-linked-lists
* FORTINET article about callbacks - https://www.fortinet.com/blog/threat-research/windows-pssetloadimagenotifyroutine-callbacks-the-good-the-bad
* 