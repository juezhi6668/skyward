use skyward_lp::{
    read, read_image, Extent, Geometry, ATTR_READONLY, ATTR_UPDATED, HEADER_FLAG_VIRTUAL_AB_DEVICE,
};
use std::path::{Path, PathBuf};

/// The first 405504 bytes of the super partition of a Xiaomi 13 Ultra on
/// OS3.0.305.0, booted from slot b: geometry, its backup and three metadata
/// slots with their backups.
fn fixture() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/ishtar-super-metadata.bin"
    ))
}

/// The fixture with the byte at each offset inverted, in a temporary file.
fn damaged(name: &str, offsets: &[usize]) -> PathBuf {
    let mut data = std::fs::read(fixture()).unwrap();
    for &at in offsets {
        data[at] ^= 0xff;
    }
    let path = std::env::temp_dir().join(format!("skyward-lp-{name}-{}", std::process::id()));
    std::fs::write(&path, data).unwrap();
    path
}

const PRIMARY_GEOMETRY: usize = 4096;
const BACKUP_GEOMETRY: usize = 8192;
/// Primary metadata copy of slot 1: after both geometry blocks and slot 0.
const PRIMARY_SLOT_1: usize = 12288 + 65536;

#[test]
fn reads_slot_b() {
    let md = read(fixture(), 1).unwrap();
    assert_eq!(
        md.geometry,
        Geometry {
            metadata_max_size: 65536,
            metadata_slot_count: 3,
            logical_block_size: 4096
        }
    );
    assert_eq!((md.major_version, md.minor_version), (10, 2));
    assert_eq!(md.header_flags, HEADER_FLAG_VIRTUAL_AB_DEVICE);
    assert!(md.damaged.is_empty());

    let names: Vec<&str> = md.partitions.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "odm_b",
            "product_b",
            "system_b",
            "system_dlkm_b",
            "system_ext_b",
            "vendor_b",
            "vendor_dlkm_b",
            "mi_ext_b",
            "odm_b-cow"
        ]
    );
    let groups: Vec<&str> = md.groups.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(groups, ["default", "qti_dynamic_partitions_b", "cow"]);
    assert_eq!(md.groups[1].maximum_size, 9_653_190_656);

    let super_dev = &md.block_devices[0];
    assert_eq!(super_dev.partition_name, "super");
    assert_eq!(
        (super_dev.first_logical_sector, super_dev.size),
        (2048, 9_663_676_416)
    );

    let vendor_dlkm = md.partition("vendor_dlkm_b").unwrap();
    assert_eq!(vendor_dlkm.attributes, ATTR_READONLY | ATTR_UPDATED);
    assert_eq!(
        vendor_dlkm.extents,
        [
            Extent::Linear {
                sectors: 81_088,
                device: 0,
                sector: 18_248_976
            },
            Extent::Linear {
                sectors: 32,
                device: 0,
                sector: 13_378_032
            },
            Extent::Linear {
                sectors: 8,
                device: 0,
                sector: 13_320_184
            },
        ]
    );
    assert_eq!(md.partition("odm_b").unwrap().sectors(), 4_078_440);
    assert_eq!(
        md.groups[md.partition("odm_b-cow").unwrap().group].name,
        "cow"
    );
}

#[test]
fn slot_a_lists_its_own_partitions() {
    let md = read(fixture(), 0).unwrap();
    // Xiaomi keeps an odm copy-on-write partition for each slot.
    assert!(md
        .partitions
        .iter()
        .all(|p| p.name.ends_with("_a") || p.name.ends_with("_a-cow")));
    assert_eq!(md.partition("system_a").unwrap().bytes(), 911_556_608);
    assert_eq!(md.partition("odm_a-cow").unwrap().bytes(), 234_942_464);
}

#[test]
fn refuses_a_slot_super_does_not_keep() {
    let err = read(fixture(), 3).unwrap_err();
    assert!(format!("{err:#}").contains("slot 3"));
}

#[test]
fn backup_geometry_stands_in_for_a_damaged_primary() {
    let path = damaged("geometry", &[PRIMARY_GEOMETRY + 10]);
    let md = read(&path, 1);
    std::fs::remove_file(&path).unwrap();
    let md = md.unwrap();
    assert_eq!(md.damaged.len(), 1);
    assert!(md.damaged[0].starts_with("primary geometry"));
    assert_eq!(md.partitions.len(), 9);
}

#[test]
fn both_geometry_copies_damaged_is_an_error() {
    let path = damaged("geometries", &[PRIMARY_GEOMETRY + 10, BACKUP_GEOMETRY + 10]);
    let md = read(&path, 1);
    std::fs::remove_file(&path).unwrap();
    assert!(format!("{:#}", md.unwrap_err()).contains("both geometry copies"));
}

#[test]
fn an_image_file_keeps_the_geometry_then_one_copy_of_the_metadata() {
    // Laid out as liblp writes an image file: the geometry block, then the
    // header and its tables with nothing after them.
    let data = std::fs::read(fixture()).unwrap();
    let header_size = u32::from_le_bytes(
        data[PRIMARY_SLOT_1 + 8..PRIMARY_SLOT_1 + 12]
            .try_into()
            .unwrap(),
    ) as usize;
    let tables_size = u32::from_le_bytes(
        data[PRIMARY_SLOT_1 + 44..PRIMARY_SLOT_1 + 48]
            .try_into()
            .unwrap(),
    ) as usize;
    let mut image = data[PRIMARY_GEOMETRY..PRIMARY_GEOMETRY + 4096].to_vec();
    image.extend_from_slice(&data[PRIMARY_SLOT_1..PRIMARY_SLOT_1 + header_size + tables_size]);
    let path = std::env::temp_dir().join(format!("skyward-lp-image-{}", std::process::id()));
    std::fs::write(&path, &image).unwrap();
    let read_back = read_image(&path);
    std::fs::write(&path, &image[..image.len() - 1]).unwrap();
    let cut = read_image(&path);
    std::fs::remove_file(&path).unwrap();
    assert_eq!(read_back.unwrap(), read(fixture(), 1).unwrap());
    assert!(
        format!("{:#}", cut.unwrap_err()).contains("tables run past"),
        "an image cut short"
    );
}

#[test]
fn backup_metadata_stands_in_for_damaged_tables() {
    // A byte in the partition table, past the 256-byte header.
    let path = damaged("tables", &[PRIMARY_SLOT_1 + 300]);
    let md = read(&path, 1);
    std::fs::remove_file(&path).unwrap();
    let md = md.unwrap();
    assert_eq!(md.damaged.len(), 1);
    assert!(md.damaged[0].contains("bad tables checksum"));
    assert_eq!(md.partition("vendor_dlkm_b").unwrap().extents.len(), 3);
}
