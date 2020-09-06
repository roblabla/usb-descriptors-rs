use usb_descriptors::*;

const DESCRIPTORS: &[u8] =
    &combine_descriptors![
        Descriptor::ConfigurationDescriptor(ConfigurationDescriptor {
            total_length: 0,
            num_interfaces: 0,
            configuration_value: 0,
            configuration_name_idx: 0,
            attributes: ConfigurationAttributes::BUS_POWERED,
            max_power: 0
        })
    ];

fn main() {}