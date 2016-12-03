# A Handful of Notes

## GCC Ordering of Local Variables on the Stack (source: StackOverflow)

> I've no idea why GCC organizes its stack the way it does (though I guess you could crack open its source or this paper and find out), but I can tell you how to guarantee the order of specific stack variables if for some reason you need to. Simply put them in a struct:

```c
void function1() {
    struct {
        int x;
        int y;
        int z;
        int *ret;
    } locals;
}
```

> If my memory serves me correctly, spec guarantees that &ret > &z > &y > &x. I left my K&R at work so I can't quote chapter and verse though.

## File Descriptors (source: Wikipedia)

<table>
	<tr>
		<th>Integer Value</th>
		<th>Name</th>
		<th>unistd.h symbolic constant</th>
		<th>stdio.h file stream</th>
	</tr>

	<tr>
		<td>0</td>
		<td>Standard input</td>
		<td>STDIN_FILENO</td>
		<td>stdin</td>
	</tr>

	<tr>
		<td>1</td>
		<td>Standard output</td>
		<td>STDOUT_FILENO</td>
		<td>stdout</td>
	</tr>

	<tr>
		<td>2</td>
		<td>Standard error</td>
		<td>STDERR_FILENO</td>
		<td>stderr</td>
	</tr>
</table>

## Process Input Tricks (source: LiveOverflow)

```bash
echo -e '`cat -`' | ./process
```

Read from stdin (fd 0), allowing for `\xNN` to be converted to actual ASCII values.

