# ****************************************************************************
#    Ledger App Bitcoin
#    (c) 2023 Ledger SAS.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ****************************************************************************

########################################
#        Mandatory configuration       #
########################################

# Application version
APPVERSION_M = 0
APPVERSION_N = 1
APPVERSION_P = 0
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

# Setting to allow building variant applications
VARIANT_PARAM = COIN
VARIANT_VALUES = babylon_vault babylon_vault_testnet

# simplify for tests
ifndef COIN
COIN = babylon_vault_testnet
endif

# Enabling DEBUG flag will enable PRINTF and disable optimizations
#DEBUG = 1

APP_DESCRIPTION = "Babylon Vault \nsecure Bitcoin vault signing\nfor the Babylon protocol."
APP_DEVELOPER = "Hoodies"

ifeq ($(COIN),babylon_vault)
APPNAME = "Babylon Vault"
BITCOIN_NETWORK = mainnet

else ifeq ($(COIN),babylon_vault_testnet)
APPNAME = "Babylon Vault Testnet"
BITCOIN_NETWORK = testnet

else ifeq ($(filter clean,$(MAKECMDGOALS)),)
$(error Unsupported COIN - use $(VARIANT_VALUES))
endif

APP_SOURCE_PATH += bitcoin_app_base/src src

# Application icons following guidelines:
# https://developers.ledger.com/docs/embedded-app/design-requirements/#device-icon
ICON_NANOX = icons/nanox_app_babylon_vault.gif
ICON_NANOSP = icons/nanosp_app_babylon_vault.gif
ICON_STAX = icons/stax_app_babylon_vault.gif
ICON_FLEX = icons/flex_app_babylon_vault.gif
ICON_APEX_P = icons/apex_p_app_babylon_vault.png

# DERIVE_CONTEXT_HASH derives its HKDF key from the device seed at m/73681862'.
# APP_LOAD_PARAMS is the intended extension point: Makefile.rules_generic includes
# Makefile.app_params *after* this file runs, which extracts --path entries and
# appends them to PATH_APP_LOAD_PARAMS before APP_INSTALL_PARAMS_DATA is computed.
APP_LOAD_PARAMS = --path "73681862'"

include bitcoin_app_base/Makefile

# arm-none-eabi-size always reports bss == total SRAM on Ledger targets: the
# linker script extends .bss to END_STACK to reserve stack space, so the bss
# column is the whole SRAM budget, not just BSS variables.  Use nm to extract
# the linker-defined _bss/_ebss/_stack/_estack labels and compute the real split.
.PHONY: app-size-report
app-size-report: $(BIN_TARGETS) $(DBG_TARGETS)
	@echo ""
	@echo "Finished Babylon-vault Ledger app ($(TARGET_NAME)) → $(BIN_DIR)/app.elf"
	@$(GCCPATH)arm-none-eabi-size $(BIN_DIR)/app.elf | \
	  awk 'NR==2 { printf "  flash  %6d B\n", $$1 }'
	@$(GCCPATH)arm-none-eabi-nm $(BIN_DIR)/app.elf 2>/dev/null | \
	  python3 -c "import sys; s={p[2]:int(p[0],16) for l in sys.stdin for p in [l.split()] if len(p)==3}; bv=s['_ebss']-s['_bss']; sk=s['_estack']-s['_stack']; print(f'  SRAM   {bv+sk:6d} B total: {bv} B BSS variables, {sk} B stack headroom')"

default: app-size-report
