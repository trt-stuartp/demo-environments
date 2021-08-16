if $::osfamily == 'Windows' {

  exec { 'Switch keyboard layout to UK':
    command   => 'Set-WinUserLanguageList -Force en-GB; Get-WinUserLanguageList; Write-Host Current User: \$env:UserName',
    provider  => powershell,
  }

  file { 'Startup script to switch keyboard layout to UK':
    ensure  => present,
    path    => 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\SetKeyboardLayoutUK.bat',
    content => 'powershell -Command "Set-WinUserLanguageList -Force en-GB; Set-WinUserLanguageList -Force en-US; Set-WinUserLanguageList -Force en-GB;',
  }

  exec { 'Switch timezone to UK':
    command   => 'Set-TimeZone "GMT Standard Time"; Write-Host Current User: \$env:UserName',
    unless => '
      $currentState = Get-TimeZone;
      $newState = Get-TimeZone -Name "*GMT*";
      $isSet = $currentState -eq $newState;
      if (!$isSet) {
        Exit 1;
      }',
    provider  => powershell,
  }

  # Download NCSC certs
  file { 'mse-ncsc-ca-der':
    ensure => present,
    path   => 'C:\\certs\\mse-ncsc-ca-der.cer',
    source => 'https://awnessusagent.blob.core.windows.net/certificates/mse-ncsc-ca-der.cer?sp=r&st=2021-01-22T00:00:00Z&se=2022-01-20T00:00:00Z&spr=https&sv=2019-12-12&sr=b&sig=xEoi0QcK%2FyS1HUXsl1lBWFdv0J83fUR9u8xOybjUq0Q%3D',
  }

  file { 'ncsc-1':
    ensure => present,
    path   => 'C:\\certs\\ncsc-1.cer',
    source => 'https://awnessusagent.blob.core.windows.net/certificates/ncsc-1.cer?sp=r&st=2021-01-22T00:00:00Z&se=2022-01-20T00:00:00Z&spr=https&sv=2019-12-12&sr=b&sig=3%2Be45LwaCbcGH%2FSYSkyUK5Qxw5mZX30Qh1IIOviojBs%3D',
  }

  file { 'ncsc-ca':
    ensure => present,
    path   => 'C:\\certs\\ncsc-ca.cer',
    source => 'https://awnessusagent.blob.core.windows.net/certificates/ncsc-ca.cer?sp=r&st=2021-01-22T00:00:00Z&se=2022-01-20T00:00:00Z&spr=https&sv=2019-12-12&sr=b&sig=bhrYjQVPjr506VtRj%2FXXR1INQPDZ2lTTOisvZDfXAlw%3D',
  }

  file { 'ncsc-root-ca':
    ensure => present,
    path   => 'C:\\certs\\ncsc-root-ca.cer',
    source => 'https://awnessusagent.blob.core.windows.net/certificates/ncsc-root-ca.cer?sp=r&st=2021-01-22T00:00:00Z&se=2022-01-20T00:00:00Z&spr=https&sv=2019-12-12&sr=b&sig=boifsbL0e9dlXfphZNVSPSpOa8mxMQ0%2FbnUeQJs6bFo%3D',
  }

  exec { 'Install certs':
    command   => 'Get-ChildItem C:/certs/ | ForEach-Object { $cert = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $_.FullName); if (Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Thumbprint -eq $cert.Thumbprint}) { Write-Host $_.Name already installed, skipping. } else { Import-Certificate -FilePath $_.FullName -CertStoreLocation Cert:\\LocalMachine\\Root; Write-Host $_.Name installed.  }}',
    provider  => powershell,
  }

  # Disable C+P on RDP
  registry_value { 'HKLM\\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableClip':
    ensure => present,
    type   => dword,
    data   => 1,
  }

  # Disable TS session drive mapping redirection
  registry_value { 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm':
    ensure => present,
    type   => dword,
    data   => 1,
  }

  # Disable TS session printer mapping redirection
  registry_value { 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCpm':
    ensure => present,
    type   => dword,
    data   => 1,
  }

  # Disable allow downloads from other PCs
  registry::value { 'DODownloadMode':
    key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization',
    value => 'DODownloadMode',
    type  => dword,
    data  => 0,
  }

  # Ensure the HBC agent is installed
  exec { 'Check HBC (dac) is running':
    command  => '
      Invoke-WebRequest -Uri "https://awnessusagent.blob.core.windows.net/hbc-agent/DACUPD-2.9.7250-release-agent_prd-gbr-windows-x86.exe?sv=2019-12-12&st=2021-02-16T09%3A35%3A50Z&se=2022-01-20T23%3A59%3A00Z&sr=b&sp=r&sig=vhfGxcaPOyPg7GracYphINUjGzmbhbV%2BffvgCcy6nyI%3D" -OutFile C:\DACUPD.exe;
      $LANIP = Test-Connection -ComputerName (hostname) -Count 1  | Select-Object IPV4Address;
      if ( $LANIP -match "10.118." ) { 
          $hint = "aw:eudpilot:pilot:4a.10.1.f2:d31924";
      } elseif ( $LANIP -match "10.119." ) {
          $hint = "aw:euds:default:4a.20.1.f2:e22293";
      }
      C:\DACUPD.exe $hint;
      Remove-Item C:\DACUPD.exe;',
    unless => '
      $serviceFound = Get-Service -Name "dac" -ErrorAction "Ignore";
      if (!$serviceFound) {
        Exit 1;
      }',
    provider  => powershell,
  }

  # Ensure Log Analytics agent is installed
  # This needs refactoring once we have sort the DEV migration and deployed changes to PROD
  exec { 'Check Log Analytics agent (AzureMonitoringAgent) is running':
    command  => '
      $LANIP = Test-Connection -ComputerName (hostname) -Count 1  | Select-Object IPV4Address;
      if ( $LANIP -match "10.118." ) { 
          az login --identity -u /subscriptions/c3cbc95c-7b24-4960-a478-a2307f7bda6a/resourceGroups/aw-dev-core-identity/providers/Microsoft.ManagedIdentity/userAssignedIdentities/aw-dev-core-lab-vm;
          $id = (az keyvault secret show -n workspace-id --vault-name aw-dev-core-build | ConvertFrom-Json).value;
          $key = (az keyvault secret show -n workspace-key --vault-name aw-dev-core-build | ConvertFrom-Json).value;
      } elseif ( $LANIP -match "10.119." ) {
          az login --identity -u /subscriptions/cef80869-1fa9-4779-84ed-a788fa98ba80/resourceGroups/AW-DevTestLab-RG/providers/Microsoft.ManagedIdentity/userAssignedIdentities/AnalystWorkstationIdentity;
          $id = (az keyvault secret show -n id --vault-name aw-workspace-keys | ConvertFrom-Json).value;
          $key = (az keyvault secret show -n key --vault-name aw-workspace-keys | ConvertFrom-Json).value;
      }

      if ($id -and $key) {
          Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?LinkId=828603" -OutFile C:\temp\MMASetup.exe;
          C:\temp\MMASetup.exe /c /t:C:\temp\extracted;

          $timeout = 20;
          $count = 0;

          $extractComplete=Test-Path -Path C:\Temp\extracted\setup.exe;
          while (!$extractComplete) {
              if ($count -eq $timeout) {
                  Write-Ouput "Extraction timed out. Exiting...";
                  Exit 1;
              }

              Write-Output "Waiting extraction to complete...";
              Start-Sleep -s 2;
              $extractComplete=Test-Path -Path C:\Temp\extracted\setup.exe;
              $count++;
          }

          Write-Output "Installing...";
          C:\Temp\extracted\setup.exe /qn NOAPM=1 ADD_OPINSIGHTS_WORKSPACE=1 OPINSIGHTS_WORKSPACE_AZURE_CLOUD_TYPE=0 OPINSIGHTS_WORKSPACE_ID="$id" OPINSIGHTS_WORKSPACE_KEY="$key" AcceptEndUserLicenseAgreement=1;
      }
      ',
    unless => '
      $serviceFound = Get-Service -Name "HealthService" -ErrorAction "Ignore";
      if (!$serviceFound) {
        Exit 1;
      }',
    provider  => powershell,
  }

  #######################################
  # UAC prompt Built-in Admins account  #
  # when application requests elevation #
  # permissions                         #
  #######################################

  # FilterAdministratorToken
  registry::value { 'FilterAdministratorToken':
    key   => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
    value => 'FilterAdministratorToken',
    type  => dword,
    data  => 1,
  }

  # Prompt Admins for credentials
  registry_value { 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin':
    ensure => present,
    type   => dword,
    data   => 5,
  }

  # Allow map drives to be available in the elevated session when UAC prompts for credentials
  registry::value { 'EnableLinkedConnections':
   key   => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
   value => 'EnableLinkedConnections',
   type  => dword,
   data  => 1,
  }
  
  # Disable printing service - CVE-2021-34527
  service { 'Spooler':
   ensure => 'stopped',
   enable => false,
  }
}
