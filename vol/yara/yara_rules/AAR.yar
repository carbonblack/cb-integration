rule AAR
{
	strings:
		$a = "MZ"

	condition:
		all of them
}