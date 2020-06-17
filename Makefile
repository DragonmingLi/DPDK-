ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk 

# binary name
APP = mydpdk

# all source are stored in SRCS-y
SRCS-y := main.c mydpdk.c 


CFLAGS += -O0 -g  -I$(SRCDIR) 
                                                
CFLAGS += $(WERROR_FLAGS)
		
#LDLIBS += -L$(subst ethtool-app,lib,$(RTE_OUTPUT))/lib
#LDLIBS += -lrte_ethtool
		
#ifeq ($(CONFIG_RTE_BUILD_SHARED_LIB),y)
#ifeq ($(CONFIG_RTE_LIBRTE_IXGBE_PMD),y)
#LDLIBS += -lrte_pmd_ixgbe
#endif
#endif


#CFLAGS += -I$(SRCDIR)
#CFLAGS += -O3 -g $(USER_FLAGS)
#CFLAGS += $(WERROR_FLAGS)

include $(RTE_SDK)/mk/rte.extapp.mk
