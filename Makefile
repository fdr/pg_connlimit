MODULE_big = pg_connlimit
OBJS = pg_connlimit.o

EXTENSION = pg_connlimit

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
