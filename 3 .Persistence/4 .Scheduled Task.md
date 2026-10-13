The Windows Task Scheduler is able to perform routine tasks based on pre-defined triggers, including:

- At a specific time on a daily, weekly, or monthly schedule.
- When the computer goes idle.
- When the system starts.
- When a user logs on.
- When a system event occurs.

An adversary can also add a scheduled task to execute payloads on a trigger of their choosing [T1053.005]

At their heart, tasks are defined in XML format.  Information about creating task definitions can be found [here](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema-elements) and [here](https://learn.microsoft.com/en-us/windows/win32/taskschd/time-trigger-example--xml-).  The `schtaskscreate` BOF can create scheduled tasks from a given XML task definition.  Here's an example that will trigger when the user logs in:
```
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>CONTOSO\pchilds</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal>
      <UserId>CONTOSO\pchilds</UserId>
    </Principal>
  </Principals>
  <Settings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
  </Settings>
  <Actions>
    <Exec>
      <Command>%LOCALAPPDATA%\Microsoft\WindowsApps\updater.exe</Command>
    </Exec>
  </Actions>
</Task>
```

Run the command `schtaskscreate \Beacon XML CREATE` without any further arguments and a file dialogue box will appear for you to browse and select the XML file.
> Replace `\Beacon` with any name you like, but it must start with the `\`.

> The task can be deleted using `schtasksdelete`.

