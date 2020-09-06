//! Easy, ergonomic API to generate USB configuration descriptors in const fn
//!
//! When working on embedded devices, it is often desirable to store USB device
//! configuration in flash memory, since it can take up quite a bit of space and
//! tends to need to stay in-memory for the lifetime of the program. But doing
//! so can be complicated: Configuration descriptors are a sort of array of
//! differently-sized types.
//!
//! In most C libraries, USB descriptors are stored as a byte array, with macros
//! used to fix endianness, and hopefully comments explaining what each field
//! is. This is problematic for several reasons:
//!
//! - There is no type safety ensuring the array is valid. A single wrong size
//!   parameter will very likely cause hard-to-debug buffer overflows in the
//!   USB stack doesn't do checks.
//!
//! - It creates complicated code that is pretty hard for newcomers to
//!   understand. It is not self-documenting.
//!
//! Our goal is to do better. We want configuration descriptors to be
//! straightforward and easy to understand, while being as performant as
//! possible at runtime. To do this, we create a common descriptor enum, and
//! a structure for every possible descriptor kind. This structure does not aim
//! to be an exact memory representation, but rather a close-enough
//! approximation from which we can generate the resulting byte array at compile
//! time.
//!
//! Furthermore, we provide compile-time checkers that validate the descriptor
//! arrays to make sure the user does not create invalid configuration
//! descriptors.
//!
//! We expect users to create an array of such Descriptor, and pass it to
//! `combine_descriptors`. This will:
//!
//! - Validate that the array of descriptor is valid and makes sense. In
//!   particular, it will cause a compile-time error if it finds a duplicate
//!   interface ID, a wrongly placed descriptor, etc...
//! - Write to the given byte array the USB-defined representation of this
//!   descriptor.
//!
//! # Usage
//!
//! ```rust
//! use usb_descriptors::*;
//! const HID_INTERFACE: u8 = 0;
//! const HID_ENDPOINT: u8 = 0;
//! const DESCRIPTORS: &[u8] = &combine_descriptors![
//!    Descriptor::ConfigurationDescriptor(ConfigurationDescriptor {
//!        total_length: 100,
//!        num_interfaces: 1,
//!        configuration_value: 1,
//!        configuration_name_idx: 0,
//!        attributes: ConfigurationAttributes::BUS_POWERED,
//!        max_power: 0x32,
//!    }),
//!    Descriptor::InterfaceDescriptor(InterfaceDescriptor {
//!        interface_num: HID_INTERFACE,
//!        alternate_setting: 0,
//!        num_endpoints: 1,
//!        interface_class: 3,
//!        interface_subclass: 0,
//!        interface_protocol: 0,
//!        interface_name_idx: 0
//!    }),
//!    Descriptor::HidDescriptor(HidDescriptor {
//!        hid_version: 0x01_11,
//!        country_code: 0,
//!        hid_descriptors_num: 1,
//!    }),
//!    Descriptor::HidDescriptorListItem(HidDescriptorListItem {
//!        descriptor_type: 0x22,
//!        descriptor_length: 33
//!    }),
//!    Descriptor::EndpointDescriptor(EndpointDescriptor {
//!        endpoint_addr: HID_ENDPOINT,
//!        attributes: 0x03,
//!        max_packet_size: 64,
//!        interval: 6
//!    }),
//! ];
//! ```

// The USB descriptors defined in this file come from
// TODO: Add convenience functions to find descriptor offsets at compile time

#![no_std]

use bitflags::bitflags;
use bitfield::bitfield;

/// Combines descriptors into a single byte array provided by the user. A null
/// descriptor is added at the end (taking two bytes).
///
/// This macro is semantically equivalent to a function with signature
/// `const fn combine_descriptors(descriptors: &[Descriptor]) -> &[u8]`,
/// but the descriptors must be passed as a literal slice.
///
/// Future versions of this crate are planning to move this macro to a const
/// function when [Rust issue 37349] is resolved for slices.
///
/// [Rust issue 37349]: https://github.com/rust-lang/rust/issues/57349
#[macro_export]
macro_rules! combine_descriptors {
    ($($descriptor:expr),* $(,)?) => {{
        // Type-check the arguments.
        let descriptors: &[Descriptor] = &[$($descriptor),*];

        $crate::assert::assert_descriptor_list_valid(descriptors, 0);

        // Assert that $data is big enough.
        let mut data = [0; 2 $(+ $descriptor.len())*];
        let mut offset_in_data = 0;
        $({
            $crate::to_arr!(arr, $descriptor);
            // TODO: Move to an API based on mutable slice references
            // BODY: Currently, Rust does not allow mutable slices in const fn.
            // BODY: This severely impacts the usability of our API, as it
            // BODY: forces us to use macros and various tricks to work around
            // BODY: the issue.
            // BODY:
            // BODY: In particular, it prevents the use of any descriptor that
            // BODY: has an arbitrary length (such as StringDescriptor).
            // BODY:
            // BODY: Blocked on https://github.com/rust-lang/rust/issues/57349
            let mut idx = 0;
            while idx < arr.len() {
                data[offset_in_data] = arr[idx];
                offset_in_data += 1;
                idx += 1;
            }
        })*

        data
    }}
}

bitflags! {
    pub struct ConfigurationAttributes: u8 {
        const BUS_POWERED   = 0b10000000;
        const SELF_POWERED  = 0b01000000;
        const REMOTE_WAKEUP = 0b00100000;
    }
}

#[derive(Debug, Clone)]
pub enum Descriptor {
    //DeviceDescriptor(),
    ConfigurationDescriptor(ConfigurationDescriptor),
    // One day.
    //StringDescriptor(StringDescriptor),
    InterfaceDescriptor(InterfaceDescriptor),
    EndpointDescriptor(EndpointDescriptor),
    InterfaceAssociationDescriptor(InterfaceAssociationDescriptor),

    HidDescriptor(hid::HidDescriptor),
    HidDescriptorListItem(hid::HidDescriptorListItem),

    CdcHeaderFunctionalDescriptor(cdc::CdcHeaderFunctionalDescriptor),
    CdcCallManagementFunctionalDescriptor(cdc::CdcCallManagementFunctionalDescriptor),
    CdcAbstractControlManagementFunctionalDescriptor(cdc::CdcAbstractControlManagementFunctionalDescriptor),
    CdcUnionFunctionalDescriptor(cdc::CdcUnionFunctionalDescriptor),
    CdcUnionSlaveInterface(cdc::CdcUnionSlaveInterface),
}

#[macro_export]
#[doc(hidden)]
macro_rules! to_arr {
    ($arr:ident, $descriptor:expr) => {
        // Type-check the descriptor.
        let descriptor: Descriptor = $descriptor;
        let arr1;
        let arr3;
        let arr4;
        let arr5;
        let arr6;
        let arr7;
        let arr8;
        let arr9;

        let $arr = match descriptor {
            Descriptor::ConfigurationDescriptor(desc) => { arr9 = desc.to_arr(); let arr: &[u8] = &arr9; arr },
            Descriptor::InterfaceDescriptor(desc) => { arr9 = desc.to_arr(); let arr: &[u8] = &arr9; arr },
            Descriptor::EndpointDescriptor(desc) => { arr7 = desc.to_arr(); let arr: &[u8] = &arr7; arr },
            Descriptor::InterfaceAssociationDescriptor(desc) => { arr8 = desc.to_arr(); let arr: &[u8] = &arr8; arr },

            Descriptor::HidDescriptor(desc) => { arr6 = desc.to_arr(); let arr: &[u8] = &arr6; arr },
            Descriptor::HidDescriptorListItem(desc) => { arr3 = desc.to_arr(); let arr: &[u8] = &arr3; arr },

            Descriptor::CdcHeaderFunctionalDescriptor(desc) => { arr5 = desc.to_arr(); let arr: &[u8] = &arr5; arr },
            Descriptor::CdcCallManagementFunctionalDescriptor(desc) => { arr5 = desc.to_arr(); let arr: &[u8] = &arr5; arr },
            Descriptor::CdcAbstractControlManagementFunctionalDescriptor(desc) => { arr4 = desc.to_arr(); let arr: &[u8] = &arr4; arr },
            Descriptor::CdcUnionFunctionalDescriptor(desc) => { arr4 = desc.to_arr(); let arr: &[u8] = &arr4; arr },
            Descriptor::CdcUnionSlaveInterface(desc) => { arr1 = desc.to_arr(); let arr: &[u8] = &arr1; arr },
        };
    };
}

impl Descriptor {
    pub const fn len(&self) -> usize {
        match self {
            Descriptor::ConfigurationDescriptor(desc) => desc.len(),
            Descriptor::InterfaceDescriptor(desc) => desc.len(),
            Descriptor::EndpointDescriptor(desc) => desc.len(),
            Descriptor::InterfaceAssociationDescriptor(desc) => desc.len(),

            Descriptor::HidDescriptor(desc) => desc.len(),
            Descriptor::HidDescriptorListItem(desc) => desc.len(),

            Descriptor::CdcHeaderFunctionalDescriptor(desc) => desc.len(),
            Descriptor::CdcCallManagementFunctionalDescriptor(desc) => desc.len(),
            Descriptor::CdcAbstractControlManagementFunctionalDescriptor(desc) => desc.len(),
            Descriptor::CdcUnionFunctionalDescriptor(desc) => desc.len(),
            Descriptor::CdcUnionSlaveInterface(desc) => desc.len(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ConfigurationDescriptor {
    /// Total byte length of the configuration descriptor and its
    /// subdescriptors.
    pub total_length: u16,
    /// Number of interfaces associated with this configuration descriptor.
    pub num_interfaces: u8,
    /// ID of this configuration descriptor.
    pub configuration_value: u8,
    /// The index of the this configuration's name in the string table.
    pub configuration_name_idx: u8,
    pub attributes: ConfigurationAttributes,
    /// Maximum power consumption of the device from the bus in this specific
    /// configuration when the device is fully operational.
    ///
    /// Expressed in 2 mA units when the device is operating in high-speed mode
    /// and in 8 mA units when operating at Gen X speed. (i.e., 50 = 100 mA when
    /// operating at highspeed and 50 = 400 mA when operating at Gen X speed).
    pub max_power: u8,
}

impl ConfigurationDescriptor {
    const LEN: usize = 9;

    pub const fn to_arr(&self) -> [u8; 9] {
        let mut data = [0; 9];
        let offset = 0;
        data[offset + 0] = self.len() as u8;
        data[offset + 1] = 0x02;
        data[offset + 2] = self.total_length.to_le_bytes()[0];
        data[offset + 3] = self.total_length.to_le_bytes()[1];
        data[offset + 4] = self.num_interfaces;
        data[offset + 5] = self.configuration_value;
        data[offset + 6] = self.configuration_name_idx;
        data[offset + 7] = self.attributes.bits();
        data[offset + 8] = self.max_power;
        data
    }

    const fn len(&self) -> usize {
        Self::LEN
    }
}

#[derive(Debug, Clone, Copy)]
pub struct InterfaceDescriptor {
    pub interface_num: u8,
    pub alternate_setting: u8,
    pub num_endpoints: u8,
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
    pub interface_name_idx: u8
}

impl InterfaceDescriptor {
    const LEN: usize = 9;

    pub const fn to_arr(&self) -> [u8; 9] {
        let mut data = [0; 9];
        let offset = 0;
        data[offset + 0] = self.len() as u8;
        data[offset + 1] = 0x04;
        data[offset + 2] = self.interface_num;
        data[offset + 3] = self.alternate_setting;
        data[offset + 4] = self.num_endpoints;
        data[offset + 5] = self.interface_class;
        data[offset + 6] = self.interface_subclass;
        data[offset + 7] = self.interface_protocol;
        data[offset + 8] = self.interface_name_idx;
        data
    }

    const fn len(&self) -> usize {
        Self::LEN
    }
}

bitfield! {
    pub struct EndpointAttributes(u8);
    impl Debug;
    pub transfer_type, set_transfer_type: 1, 0;
    pub synchronisation_type, set_synchronisation_type: 3, 2;
    pub usage_type, set_usage_type: 5, 4;
}

#[derive(Debug, Clone, Copy)]
pub struct EndpointDescriptor {
    pub endpoint_addr: u8,
    pub attributes: u8,
    pub max_packet_size: u16,
    pub interval: u8
}

impl EndpointDescriptor {
    const LEN: usize = 7;

    pub const fn to_arr(&self) -> [u8; 7] {
        let mut data = [0; 7];
        let offset = 0;
        data[offset + 0] = self.len() as u8;
        data[offset + 1] = 0x05;
        data[offset + 2] = self.endpoint_addr;
        data[offset + 3] = self.attributes;
        data[offset + 4] = self.max_packet_size.to_le_bytes()[0];
        data[offset + 5] = self.max_packet_size.to_le_bytes()[1];
        data[offset + 6] = self.interval;
        data
    }

    const fn len(&self) -> usize {
        Self::LEN
    }
}

/// The Interface Association Descriptor is used to describe that two or more
/// interfaces are associated to the same function. An "association" includes
/// two or more interfaces and all of their alternate setting interfaces. A
/// device must use an Interface Association descriptor for each device function
/// that requires more than one interface.
///
/// An interface association descriptor must be located before the set of
/// interface descriptors (including all alternate settings) for the interfaces
/// it associates.
///
/// The interface association descriptor includes function class, subclass, and
/// protocol fields. The values in these fields can be the same as the interface
/// class, subclass, and protocol values from any one of the associated
/// interfaces. The preferred implementation, for existing device classes, is to
/// use the interface class, subclass, and protocol field values from the first
/// interface in the list of associated interfaces.
#[derive(Debug, Clone, Copy)]
pub struct InterfaceAssociationDescriptor {
    pub first_interface: u8,
    pub interface_count: u8,
    pub function_class: u8,
    pub subfunction_class: u8,
    pub function_protocol: u8,
    pub function_name_idx: u8
}

impl InterfaceAssociationDescriptor {
    const LEN: usize = 8;

    pub const fn to_arr(&self) -> [u8; 8] {
        let mut data = [0; 8];
        let offset = 0;
        data[offset + 0] = self.len() as u8;
        data[offset + 1] = 0x0b;
        data[offset + 2] = self.first_interface;
        data[offset + 3] = self.interface_count;
        data[offset + 4] = self.function_class;
        data[offset + 5] = self.subfunction_class;
        data[offset + 6] = self.function_protocol;
        data[offset + 7] = self.function_name_idx;
        data
    }

    const fn len(&self) -> usize {
        Self::LEN
    }
}

/*/// Note: Can only be used with string descriptors of less than 32 bytes. This
/// is because of restrictions in const generics.
struct StringDescriptor {
    s: &'static str
}

impl StringDescriptor {
    const fn len(&self) {
        self.s.len() + 2
    }

    const fn to_arr(&self) -> [u8; 34] {
        let s= self.s.as_bytes();
        [
            self.len() as u8, 0x03,
                if s.len() > 00 { s[00] } else { 0 },
                if s.len() > 01 { s[01] } else { 0 },
                if s.len() > 02 { s[02] } else { 0 },
                if s.len() > 03 { s[03] } else { 0 },
                if s.len() > 04 { s[04] } else { 0 },
                if s.len() > 05 { s[05] } else { 0 },
                if s.len() > 06 { s[06] } else { 0 },
                if s.len() > 07 { s[07] } else { 0 },
                if s.len() > 08 { s[08] } else { 0 },
                if s.len() > 09 { s[09] } else { 0 },
                if s.len() > 10 { s[10] } else { 0 },
                if s.len() > 11 { s[11] } else { 0 },
                if s.len() > 12 { s[12] } else { 0 },
                if s.len() > 13 { s[13] } else { 0 },
                if s.len() > 14 { s[14] } else { 0 },
                if s.len() > 15 { s[15] } else { 0 },
                if s.len() > 16 { s[16] } else { 0 },
                if s.len() > 17 { s[17] } else { 0 },
                if s.len() > 18 { s[18] } else { 0 },
                if s.len() > 19 { s[19] } else { 0 },
                if s.len() > 20 { s[20] } else { 0 },
                if s.len() > 21 { s[21] } else { 0 },
                if s.len() > 22 { s[22] } else { 0 },
                if s.len() > 23 { s[23] } else { 0 },
                if s.len() > 24 { s[24] } else { 0 },
                if s.len() > 25 { s[25] } else { 0 },
                if s.len() > 26 { s[26] } else { 0 },
                if s.len() > 27 { s[27] } else { 0 },
                if s.len() > 28 { s[28] } else { 0 },
                if s.len() > 29 { s[29] } else { 0 },
                if s.len() > 30 { s[30] } else { 0 },
                if s.len() > 31 { s[31] } else { 0 },
        ]
    }
}*/

#[doc(hidden)]
pub mod assert {
    use super::*;

    #[derive(Clone, Copy)]
    struct ConfigurationState {
        /// bitmap of interface IDs that have already been found. Used to check
        /// if a bump in interfaces_found is necessary, and for the IAD
        /// descriptor check.
        found_interface_nums: [u8; 256 / 8],
        /// bitmap of interface + alternate IDs that have already been found.
        /// Used to check for invalid duplicates interface configurations.
        found_interface_ids: [u8; 256 * 256 / 8], // needs 256 * 256 bits
        /// The number of interface descriptors expected to be found for this
        /// configuration descriptor.
        interfaces_expected: u8,
        /// The actual number of interfaces found.
        interfaces_found: u8,
        iad_info: Option<InterfaceAssociationDescriptor>,
        bytes_found: usize,
    }

    impl ConfigurationState {
        const fn new(desc: &ConfigurationDescriptor) -> ConfigurationState {
            ConfigurationState {
                found_interface_nums: [0; 256 / 8],
                found_interface_ids: [0; 256 * 256 / 8],
                interfaces_expected: desc.num_interfaces,
                interfaces_found: 0,
                iad_info: None,
                bytes_found: 0,
            }
        }
    }

    struct InterfaceState {
        endpoints_expected: u8,
        endpoints_found: u8,
    }

    impl InterfaceState {
        const fn new(desc: &InterfaceDescriptor) -> InterfaceState {
            InterfaceState {
                endpoints_expected: desc.num_endpoints,
                endpoints_found: 0
            }
        }
    }


    const fn assert_interface_valid(descriptors: &[Descriptor], offset: usize, mut state: InterfaceState) -> (usize, InterfaceState) {
        if offset == descriptors.len() {
            return (offset, state);
        }
        match descriptors[offset] {
            Descriptor::ConfigurationDescriptor(..) | Descriptor::InterfaceDescriptor(..) | Descriptor::InterfaceAssociationDescriptor(..) => {
                return (offset, state);
            }
            Descriptor::EndpointDescriptor(..) => {
                state.endpoints_found += 1;
                assert_interface_valid(descriptors, offset + 1, state)
            },
            _ => {
                // TODO: HID, IAD, CDC validity
                assert_interface_valid(descriptors, offset + 1, state)
            }
        }
    }

    const fn assert_configuration_valid(descriptors: &[Descriptor], offset: usize, mut state: ConfigurationState) -> (usize, ConfigurationState) {
        if offset == descriptors.len() {
            return (offset, state);
        }
        match descriptors[offset] {
            Descriptor::ConfigurationDescriptor(..) => return (offset, state),
            Descriptor::InterfaceAssociationDescriptor(..) => {
                // TODO
                assert_configuration_valid(descriptors, offset + 1, state)
            }
            Descriptor::InterfaceDescriptor(desc) => {
                let interface_id = (desc.interface_num as usize * 256) + (desc.alternate_setting as usize);
                let interface_num = desc.interface_num as usize;
                let duplicate_iface = state.found_interface_ids[interface_id / 8] & (1 << (desc.interface_num % 8)) != 0;
                ["Duplicate interface_num/alternate_setting found within the same configuration"][duplicate_iface as usize];

                if state.found_interface_nums[interface_num / 8] & (1 << (desc.interface_num % 8)) == 0 {
                    state.interfaces_found += 1;
                }
                state.found_interface_ids[interface_id / 8] |= 1 << (interface_id % 8);
                state.found_interface_nums[interface_num / 8] |= 1 << (interface_num % 8);
                let iface_state = InterfaceState::new(&desc);
                let (offset, iface_state) = assert_interface_valid(descriptors, offset + 1, iface_state);
                let wrong_endpoint_num = iface_state.endpoints_expected != iface_state.endpoints_found;
                ["Wrong number of endpoints in interface"][wrong_endpoint_num as usize];
                assert_configuration_valid(descriptors, offset, state)
            },
            _ => {
                ["Unexpected descriptor type"][always_true() as usize];
                loop {}
            }
        }
    }

    pub const fn assert_descriptor_list_valid(descriptors: &[Descriptor], offset: usize) {
        if offset == descriptors.len() {
            return;
        }

        match descriptors[offset] {
            Descriptor::ConfigurationDescriptor(desc) => {
                let state = ConfigurationState::new(&desc);
                let (_offset, state) = assert_configuration_valid(descriptors, offset + 1, state);
                let wrong_num_interfaces = state.interfaces_found != state.interfaces_expected;
                ["Configuration has wrong num_interfaces value."][wrong_num_interfaces as usize];
            },
            _ => {
                let always_true = descriptors.len() == 0;
                ["Configuration descriptor not found."][always_true as usize];
            }
        }
    }
    pub const fn assert_generation_valid(data: &[u8], offset: usize) {
        if offset == data.len() {
            return;
        } else {
            let len = data[offset];
            let invalid_desc_len = len < 2;
            ["0 or 1 length descriptor found!"][invalid_desc_len as usize];
            return assert_generation_valid(data, offset + len as usize);
        }
    }
    const fn always_true() -> bool {
        true
    }
}

mod hid;
mod cdc;

pub use hid::*;
pub use cdc::*;

#[cfg(test)]
mod tests {
    #[test]
    fn ui() {
        let t = trybuild::TestCases::new();
        t.pass("tests/compile-pass/*.rs");
        t.compile_fail("tests/compile-fail/*.rs");
    }
}