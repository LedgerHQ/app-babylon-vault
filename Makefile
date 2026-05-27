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
VARIANT_VALUES = app_babylon_vault app_babylon_vault_testnet

# simplify for tests
ifndef COIN
COIN = app_babylon_vault_testnet
endif

# Enabling DEBUG flag will enable PRINTF and disable optimizations
#DEBUG = 1

APP_DESCRIPTION = "Babylon Vault \nsecure Bitcoin vault signing\nfor the Babylon protocol."
APP_DEVELOPER = "Hoodies"

ifeq ($(COIN),app_babylon_vault)
APPNAME = "Babylon Vault"
BITCOIN_NETWORK = mainnet

else ifeq ($(COIN),app_babylon_vault_testnet)
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

include bitcoin_app_base/Makefile
