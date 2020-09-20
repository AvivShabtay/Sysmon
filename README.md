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

## ToDo
- [ ] Add user-mode application to consume events
- [ ] Create Service - start routine, stop routine
- [ ] Create launch routine: load the driver, start consuming events, add events to log file
---

## Useful links
* Pavel Yosifuvich book - https://leanpub.com/windowskernelprogramming
* More about kernel callbacks - https://www.codemachine.com/article_kernel_callback_functions.html
* Tutorial from MSDN about Linked-Lists - https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/singly-and-doubly-linked-lists
* FORTINET article about callbacks - https://www.fortinet.com/blog/threat-research/windows-pssetloadimagenotifyroutine-callbacks-the-good-the-bad
* 