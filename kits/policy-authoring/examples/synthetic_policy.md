# Synthetic Cloud Standard (fictional)

## 4.2 Cost center tag
Production resources must have a non-empty CostCenter tag.

## 4.3 Inherited cost center
When a resource lacks CostCenter, inherit from the resource group if present.

## 5.1 Permitted regions
Production resources must be deployed in eastus, eastus2, or centralus.

## 6.1 Diagnostic destination
Key production resources must send diagnostics to an approved Log Analytics workspace.

## 7.4 Restore testing
Owners must complete a quarterly restore test. Backup enrollment alone is insufficient.
