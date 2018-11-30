#include "device_factory.h"

namespace Vdev {

cxx::H_list_t<Device_type> Device_type::types(true);
Factory *Factory::pass_thru;

}
