# Modern BIOS Management (archived compatibility source)

> **Maintenance moved:** Active maintenance of
> `Invoke-CMDownloadBIOSPackage.ps1` and the Dell, HP, Lenovo, and Microsoft
> BIOS apply scripts now takes place in
> [`vartaxe/DriverAutomationTool`](https://github.com/vartaxe/DriverAutomationTool/tree/main/Driver%20Automation%20Tool/Scripts).
> This repository is retained read-only for historical references, commit
> provenance, and users who need the former standalone layout. Do not open new
> maintenance work here.

This repository is a maintained fork of [MSEndpointMgr/ModernBIOSManagement](https://github.com/MSEndpointMgr/ModernBIOSManagement), preserving the upstream MIT license and attribution. It contains community maintenance updates while remaining compatible with the upstream project.

For implementation instructions, please go to https://www.msendpointmgr.com/modern-bios-management

## Supported hardware and package-selection modes

BIOS package selection and application are implemented for Dell, HP/Hewlett-Packard, Lenovo, and Microsoft devices. This scope matches the downloader's manufacturer allow-list and the four dedicated apply scripts: `Invoke-DellBIOSUpdate.ps1`, `Invoke-HPBIOSUpdate.ps1`, `Invoke-LenovoBIOSUpdate.ps1`, and `Invoke-MicrosoftBIOSUpdate.ps1`.

The debug-mode manufacturer values Fujitsu, Panasonic, Viglen, and AZW are inventory and package-matching test inputs; they do not represent supported BIOS apply implementations. Acer, ASUS, Getac, Intel/NUC, MSI/Micro-Star, GIGABYTE, Dynabook/Toshiba, and generic OEM BIOS flows are not implemented. Getac's published WMI interface can manage supported BIOS settings, but that is distinct from downloading or flashing firmware and is outside this project's current scope. MSI Center, GIGABYTE Control Center, `@BIOS`, M-FLASH, guessed silent switches, and generic AMI flashing tools are not invoked. Those vendors remain driver-package recognition/manual-matching targets in ModernDriverManagement only; adding a manufacturer name here without a documented version contract, unattended updater, exit-code handling, BitLocker behavior, reboot semantics, and hardware validation would falsely imply safe firmware support. Alienware devices may follow the Dell path only when Dell tooling supports the device and the package uses compatible Dell metadata; Alienware is not separately validated by this project.

The modern downloader supports two package-selection sources. AdminService mode queries ConfigMgr for package metadata online. `XMLPackage` mode reads package metadata offline from a pre-downloaded `DriverPackages.xml` file and uses `XMLDeploymentType` to choose `BareMetal` or `BIOSUpdate` behavior. In this documentation, online and offline describe how package-selection metadata is obtained; they do not refer to servicing a mounted or offline Windows image.

BIOS package matching uses the manufacturer, model/SystemSKU and BIOS version or release date, not the Windows release or build number. Windows feature updates do not require a version-mapping entry in these scripts. That includes Windows 11 26H1 (build 28000, a specialized release for selected new hardware) and Windows 11 26H2 (build 26300, the annual enablement-package release). Microsoft Surface firmware delivered through driver packages is still handled as such.

This package-selection independence does not override the deployment platform's support matrix. Windows 11 26H1 is a new-hardware-only release rather than a general upgrade target, and Configuration Manager 2509 does not support Windows 11 26H2 clients; use Configuration Manager 2603 or later for 26H2 task sequences.

The scripts use `Get-CimInstance` for local hardware, ConfigMgr client, time-zone and BitLocker queries. In WinPE, include the WinPE-WMI, WinPE-NetFX, WinPE-Scripting and WinPE-PowerShell optional components and their dependencies. CIM queries are local and do not require WinRM configuration.

Replacing WMI cmdlets does not make the entire solution PowerShell 7 compatible: the legacy downloader still uses `New-WebServiceProxy`, which requires Windows PowerShell. Continue using the supported ConfigMgr task-sequence PowerShell environment.

Run the scripts under `.\Tests` for isolated regression checks; they mock hardware queries and do not download packages or flash firmware.

## Dell Update Package (DUP) exit code handling

`Invoke-DellBIOSUpdate.ps1` evaluates Dell's documented DUP exit codes in one shared handler used by both the WinPE and full OS branches. Exit codes are compared as integers; the previous `-match "0|2"` regex comparison also accepted 10, 12, 20 and 120 as success.

| Code | Meaning | Script result |
| --- | --- | --- |
| 0 | Successful | Success |
| 1 | General update failure | Failure, exits 1 |
| 2, 14 | Reboot required (14 with unmet soft dependencies) | Success, sets `SMSTSBIOSUpdateRebootRequired` |
| 3 | Soft dependency error, typically the same or a newer BIOS is already installed | Warning, not a failure |
| 6 | The package is restarting the system itself | Success, the script does not request a second reboot |
| 13 | Successful with unmet soft dependencies | Warning, treated as success |
| 15, 16 | Full power cycle required | Warning, sets `SMSTSBIOSUpdateColdBootRequired` only |
| 17 | Update successful, rollback image creation failed | Warning, treated as success |
| 18 | Update successful; package initiated the virtual AC power cycle | Warning, treated as success |
| 19 | Update successful; manual AC power cycle required | Warning, sets `SMSTSBIOSUpdateColdBootRequired` only |
| 20 | Update successful, post-install script failed | Warning, treated as success; review the Dell log |
| 4 | Hard dependency error | Failure, exits 4 |
| 5 | Qualification error, cannot be bypassed with the force switch | Failure, exits 5 |
| 10 | Unspecified client-BIOS utility error (examples include battery/AC power, embedded-controller or hardware failures) | Failure, exits 10 and preserves the Dell result for diagnosis |
| any other | Unhandled failure, including the Linux-only code 9 | Failure, exits with the original Dell exit code |

Failure paths now exit with the original Dell exit code instead of a blanket `exit 1`, so ConfigMgr or Intune can distinguish failure classes.

`SMSTSBIOSUpdateColdBootRequired` is a new task-sequence variable. Codes 15, 16 and 19 require a full or manual AC power cycle rather than a warm restart, so the script records only the stronger requirement and lets the task sequence decide when to shut the machine down. It deliberately does not also set `SMSTSBIOSUpdateRebootRequired`, because a warm `Restart Computer` step does not satisfy those results.

For a consistent task-sequence contract, HP and Microsoft code 3010 and Lenovo WinUPTP code 0 set `SMSTSBIOSUpdateRebootRequired`. HP code 0 is plain success. Lenovo exit code 1073807364 (`0x3FFF0004`) is not present in Lenovo's published WinUPTP result tables, so the script logs it as an unverified failure and requires review of `winuptp.log` instead of reporting success.

## AdminService authentication security

The modern downloader does not install or update PowerShell Gallery modules during
deployment. External AdminService/CMG authentication uses the configured tenant,
client, application, user name, and password values to request an OAuth token
directly. This resource-owner-password flow is legacy and incompatible with accounts
that require MFA or passwordless authentication. Where the target API supports
app-only access, migrate unattended workloads to a service principal with a
certificate credential; review Microsoft's
[ROPC limitations and migration guidance](https://learn.microsoft.com/entra/identity-platform/v2-oauth-ropc).

For internal AdminService authentication, the configured user name is attempted
first. If it receives `401 Unauthorized`, the script can retry inferred UPN and
down-level domain-qualified forms. This is compatibility handling for environments
that reject a bare account name, not a Microsoft-documented ConfigMgr 2603
UPN-only requirement. Prefer an explicit UPN to avoid ambiguous domain inference,
and validate the account format and policy in your own site.

## Transport and BitLocker safety

Both downloaders enforce normal HTTPS certificate validation. Configure the ConfigMgr AdminService or legacy web service with a server-authentication certificate that chains to a root trusted by the full operating system and the WinPE boot image. The scripts do not install a global certificate callback or accept an untrusted/self-signed endpoint. Import the issuing CA chain into WinPE when an enterprise PKI is used.

The Dell, HP and Lenovo update scripts query BitLocker through `Win32_EncryptableVolume`, fail closed if protection state cannot be determined, and suspend protection for one reboot only (`manage-bde -RebootCount 1`). If the update fails or succeeds without requiring a reboot, the script immediately re-enables protection and verifies the protected state. Results that require a reboot or cold boot retain the bounded suspension so the staged firmware can be applied safely.

## Virtual machine detection

A virtual machine has no physical flash chip. The guest BIOS/UEFI is a binary template owned by the hypervisor and is changed by updating the hypervisor host or raising the VM hardware compatibility version, never by running a vendor firmware payload inside the guest. Running a Dell Update Package in a guest returns exit code 5 (QUAL_HARD_ERROR), which `Invoke-DellBIOSUpdate.ps1` correctly treats as a hard failure and exits 5, failing the task sequence.

`Invoke-CMDownloadBIOSPackage.ps1` previously carried two separate inline virtual machine model lists that had already drifted apart, so a VMware guest could pass one gate and fail the other. Both call sites now use a single `Test-VirtualMachinePlatform` helper that matches the known Hyper-V, VMware, VirtualBox, Xen, KVM/QEMU, Parallels, Google Compute Engine and Nutanix AHV model strings, with a manufacturer regex fallback. `Microsoft` is deliberately absent from that regex because Surface devices report `Microsoft Corporation` exactly like Hyper-V guests; Hyper-V is matched on the `Virtual Machine` model string instead.

The four vendor flash scripts previously had no virtual machine detection at all, so invoking one directly outside the downloader attempted a flash and failed hard. Each now uses the same model strings and manufacturer fallbacks, including AWS EC2, OpenStack and Google, and exits 0 with a severity 2 log entry before any BitLocker suspension or working directory change. A guest is therefore skipped cleanly rather than leaving BitLocker suspended behind a failed step.

`Invoke-CMDownloadBIOSPackage_Legacy.ps1` keeps its inline model-only list, widened to the same model strings, to preserve the frozen state of that script.

Hypervisor integration suites such as VMware Tools, Hyper-V Integration Services and VirtIO are driver and tooling packages, not firmware, and remain out of scope for this solution.

## Secure Boot certificate expiry (2026)

Microsoft's 2011 Secure Boot certificates expire on three dates: Microsoft Corporation KEK CA 2011 on June 24, Microsoft UEFI CA 2011 (certificate subject `Microsoft Corporation UEFI CA 2011`) on June 27, and Microsoft Windows Production PCA 2011 on October 19, 2026. Their replacements span the KEK and DB: `Microsoft Corporation KEK 2K CA 2023`, `Windows UEFI CA 2023`, `Microsoft UEFI CA 2023`, and `Microsoft Option ROM UEFI CA 2023`.

An untransitioned system continues to boot and receive standard Windows updates after expiry, but it cannot receive future boot-chain protections that depend on the 2023 trust anchors. Do not use Event IDs 1796 or 1803 as general expiry indicators: 1796 is an unexpected Secure Boot update error and 1803 identifies a missing OEM-signed KEK. Microsoft documents `UEFICA2023Status=Updated` and Event ID 1808 as completion signals; Event 1801 indicates incomplete servicing and Event 1795 a firmware error.

`Test-SecureBootCertificateStatus` is read-only and reports two task-sequence variables:

- `SecureBootCertificate2023Present` is `True` only when `Windows UEFI CA 2023` is observed in the UEFI DB.
- `SecureBootCertificate2023Status` distinguishes `Updated`, `Present`, `NotPresent`, `Disabled`, `Unavailable`, and `Error`. `Updated` requires the Windows servicing value `UEFICA2023Status=Updated`, which confirms the complete certificate and 2023-signed Boot Manager transition; DB presence alone reports `Present`.

The check never blocks, delays, or alters a BIOS flash. It runs before the virtual-machine gate because VMs also store certificates in virtual NVRAM. Missing Secure Boot cmdlets, legacy BIOS, disabled Secure Boot, and WinPE limitations are reported without terminating the script under `$ErrorActionPreference = "Stop"`.

Remediation is coordinated by Windows servicing with the physical or virtual firmware; it is not universally host-only:

| Platform | Current remediation model |
| --- | --- |
| Physical hardware | Apply supported Windows servicing; install an OEM firmware update first when the firmware cannot process authenticated DB/KEK updates. |
| VMware vSphere | ESXi 8.0 U3j adds automated PK remediation for vTPM-disabled VMs. vTPM-enabled VMs on ESXi 8.x still need Broadcom's manual procedure; the capsule path requires ESX 9.1.1.0+, VMware Tools 13.1.5+, a supported Windows guest, and the July 2026 Windows CU. Update KEK/DB through the guest OS after PK readiness. |
| Hyper-V | For long-lived Generation 2 VMs, apply the updates through Windows when the virtual firmware supports authenticated Secure Boot writes; monitor `UEFICA2023Status` and the documented events. Windows Server may require an administrator-initiated deployment rather than client Controlled Feature Rollout. |
| Azure Trusted Launch / Confidential VMs | Updates are initiated through Windows servicing inside the guest and rely on Azure platform support for virtual-firmware writes. VMs created after March 2024 typically already contain the 2023 firmware certificates but still require the updated Boot Manager. |
| Proxmox VE / QEMU | New EFI disks created with `pve-edk2-firmware` 4.2025.05-1 or later contain both certificate generations. For older EFI disks, shut down the VM and use **Disk Action > Enroll Updated Certificates** or `qm enroll-efi-keys`; suspend BitLocker protectors first. |

Authoritative references:

- [Microsoft: Windows Secure Boot certificate expiration and CA updates](https://support.microsoft.com/en-us/servicing/os/secure-boot/2025/06/windows-secure-boot-certificate-expiration-and-ca-updates)
- [Microsoft: Guidance for IT professionals and organizations](https://support.microsoft.com/en-us/servicing/os/secure-boot/2025/06/secure-boot-certificate-updates-guidance-for-it-professionals-and-organizations)
- [Microsoft: Registry monitoring and deployment keys](https://support.microsoft.com/en-us/servicing/os/secure-boot/2025/09/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates)
- [Microsoft: Secure Boot DB, DBX, and KEK events](https://support.microsoft.com/en-us/servicing/os/windows/2022/06/secure-boot-db-and-dbx-variable-update-events)
- [Microsoft: Azure Trusted Launch and Confidential VM guidance](https://support.microsoft.com/en-us/servicing/os/secure-boot/docs/2026/03/secure-boot-update-from-2011-to-2023-certificates-trusted-launch-vms-tvm-and-confidential-vms-cvm)
- [Broadcom: vSphere Secure Boot certificate expiration FAQ](https://knowledge.broadcom.com/external/article/423893/secure-boot-certificate-expirations-and.html)
- [Proxmox: 2023 certificate enrollment documentation change](https://lists.proxmox.com/pipermail/pve-devel/2026-January/078081.html)
