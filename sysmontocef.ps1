# @Infosec_Badger & @mokosec
# Powershell script to pull Sysmon process creation logs, convert them to CEF format and send directly to a syslog server
# Some filtering examples for noise reduction
# 20170713
# Run as SYSTEM or admin, user will need permission to view event logs
# 


Function read_sysmon_log {
	# create the last event file if not exist
	if (-not (Test-Path "$lastevent_file")) {
		New-Item "$lastevent_file" -ItemType file | Out-Null
	}

	# read the last event or set to -2 hours
	try
	{
		$lastevent = [IO.File]::ReadAllText($lastevent_file)
		# time is string in file but in local time
		$lastevent =  [datetime]$lastevent
		write-host last event from file is $lastevent
	}
	Catch
	{
		write-host last event file not found
	}

	# set a default lookback time if this is the first run
	if	(-not  $lastevent)	{
		# Just go back 2 hours
		$lastevent = (Get-Date).AddHours(-2)
		write-host last event not found default now $lastevent
	}

	# Get events
	$events = Get-WinEvent -filterhashtable @{ logname = "Microsoft-Windows-Sysmon/Operational"; Id = 1; StartTime=$lastevent } -erroraction silentlycontinue
	$event_count = $events.Count
	
	write-host Count: $event_count  start: $lastevent

	$proc = Get-CimInstance Win32_Process -Filter "name = 'explorer.exe'"
	$user = Invoke-CimMethod -InputObject $proc -MethodName GetOwner
	$suser = $user.user
	$suser = $suser.replace("\", "\\")
	$shost = $env:computername
	$temp = $lastevent_file.replace("\", "\\")
	
	# Do some stats
	$time = Get-Date -Format ("MMM dd yyyy HH:mm:ss")
	$src = (gwmi Win32_NetworkAdapterConfiguration | ? { $_.IPAddress -ne $null -and $_.IPAddress -notlike "169.254.*" }).ipaddress
	$line = "end=$time suser=$suser duser=$duser shost=$shost src=$src cs1=Status Check cs6=$temp cs5=$lastevent cn1=$event_count"
	$list.Add("$line")

	
	$first = 1
	if($events)	{
		foreach ($event in $events)	{
			$eventXML = [xml]$event.ToXml()
			if ($eventXML.Event.EventData.Data[0].'#text' -ge $lastevent)		{
				# Grab the date of the latest element
				if ($first)	{
					$lasteventtime = $eventXML.Event.EventData.Data[0].'#text'
					$lasteventtime = Get-LocalTime($lasteventtime)
					$first = 0
					#write-host last event is : $lasteventtime :
				}
				$time = Get-LocalTime($eventXML.Event.EventData.Data[0].'#text')
				$time = $time.ToString("MMM dd yyyy HH:mm:ss")
				$c_image = $eventXML.Event.EventData.Data[3].'#text'
				$c_cmdline = $eventXML.Event.EventData.Data[4].'#text'
				$duser = $eventXML.Event.EventData.Data[6].'#text'
				$duser = $duser.replace("\", "\\")		
				$p_image = $eventXML.Event.EventData.Data[14].'#text'
				$p_cmdline = $eventXML.Event.EventData.Data[15].'#text'

				# P_CMDLINE
				# Filter
				if ($p_image -eq 'C:\Windows\System32\SearchIndexer.exe')	{
					continue
				}
				
				# P_CMDLINE
				# Filter
				if ($p_cmdline -eq 'C:\WINDOWS\System32\svchost.exe -k netsvcs' -and $c_image -eq 'C:\Windows\System32\raserver.exe')	{
					continue
				}				

				# C_IMAGE
				# Filter
				if ($c_image -eq 'C:\Windows\System32\gpupdate.exe')	{
					continue
				}

				# C_CMDLINE
				# Filter
				if ($c_cmdline -eq 'C:\Windows\System32\igfxTray.exe')	{
					continue
				}

				$p_image = $p_image.replace("\", "\\")
				$p_cmdline = $p_cmdline.replace("\", "\\")
				$c_image = $c_image.replace("\", "\\")
				$c_cmdline = $c_cmdline.replace("\", "\\")
			}
			$line = "end=$time suser=$suser duser=$duser shost=$shost src=$src cs1=$p_image cs2=$p_cmdline cs3=$c_image cs4=$c_cmdline"
			$list.Add("$line")
		}
		#$lasteventtime =  [datetime]$lasteventtime
		Write-Output "$lasteventtime" | Out-File $lastevent_file
	}
	return $list
}

function Get-LocalTime($UTCTime)	{
	#https://blog.tyang.org/2012/01/11/powershell-script-convert-to-local-time-from-utc/

	# in this case the time is not an object yet
	$UTCTime =  [datetime]$UTCTime
	$strCurrentTimeZone = (Get-WmiObject win32_timezone).StandardName
	$TZ = [System.TimeZoneInfo]::FindSystemTimeZoneById($strCurrentTimeZone)
	$LocalTime = [System.TimeZoneInfo]::ConvertTimeFromUtc($UTCTime, $TZ)
	Return $LocalTime
}

function output_message($list) {
	# writes to file for debugging
	write-host file: $event_file
	foreach ($item in $list)	{
		$item >> $event_file
	}
}

function Send-SyslogMessage	{
	# https://poshsecurity.com/blog/2014/7/1/sending-syslog-messages-from-powershell.html

	$timestamp = Get-Date -Format "yyyy:MM:dd:-HH:mm:ss zzz"
	
	# Create a UDP Client Object
	$udpclient = New-Object System.Net.Sockets.UdpClient
	$udpclient.Connect($server, $udpport)
	$header = "<6>$timestamp $hostname CEF:0|SOC|sysmon|||sysmon|3|"

	# create an ASCII Encoding object
	$encoding = [System.Text.Encoding]::ASCII
 
 	foreach ($item in $list)	{
		$message = $header + $item
		# Convert into byte array representation
		($byte_message = $encoding.GetBytes($message)) > $null

		# Send the Message
		$UDPCLient.Send($byte_message, $byte_message.Length)	| out-null
		
	}
 }


#########################################
# Main

# Set last event and output file
$lastevent_file = $env:temp + '\sysmon.txt'
$event_file = $env:temp + '\sysmon_events.txt'

$count = 0

while (1)	{
	$list = New-Object System.Collections.Generic.List[System.Object]
	# Read the sysmon log into list
	$list = read_sysmon_log

	# debug output to file
	#output_message($list)

	# Check for live server and send via syslog (use an ESM CEF syslog connector UDP)
	$server = "192.168.56.1"
	$udpport = "513"
	$hostname = $env:computername

	# Test for a connection or EXIT	
	if (Test-Connection -ComputerName "$server" -Count 2 -Quiet)	{
		Send-SyslogMessage
	}
	else	{
		write-host syslog server not available EXITING !
		# Might want to exit if syslog server isn't available
		#exit
	}
	$list = $null
	$count++
	sleep(300)
}




