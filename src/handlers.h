#ifndef INCLUDE_SRC_HANDLERS_H_
#define INCLUDE_SRC_HANDLERS_H_

#include "common.h"
#include "driver.h"
#include "inteldef.h"

uintr_receiver_id_t register_handler(_uintr_handler_args *handler_args);

int unregister_handler(uintr_receiver_id_t id);

#endif // INCLUDE_SRC_HANDLERS_H_
