use crate::status::StatusSnapshot;
use ksni::{menu, Icon, Status, Tray};

static LOGO_BYTES: &[u8] = include_bytes!("../../assets/mykey-logo.png");

pub struct MyKeyTray {
    icons: Vec<Icon>,
    snapshot: StatusSnapshot,
}

impl MyKeyTray {
    pub fn new(snapshot: StatusSnapshot) -> Self {
        Self {
            icons: load_icons(),
            snapshot,
        }
    }

    pub fn set_snapshot(&mut self, snapshot: StatusSnapshot) {
        self.snapshot = snapshot;
    }

    pub fn refresh_status_cache(&mut self) {
        self.snapshot = StatusSnapshot::gather();
    }
}

impl Tray for MyKeyTray {
    fn id(&self) -> String {
        "mykey-tray".into()
    }

    fn title(&self) -> String {
        "MyKey".into()
    }

    fn status(&self) -> Status {
        if self.snapshot.daemon_is_active() {
            Status::Active
        } else {
            Status::NeedsAttention
        }
    }

    fn icon_pixmap(&self) -> Vec<Icon> {
        self.icons.clone()
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.refresh_status_cache();
    }

    fn secondary_activate(&mut self, _x: i32, _y: i32) {
        self.refresh_status_cache();
    }

    fn menu(&self) -> Vec<menu::MenuItem<Self>> {
        let mut items = vec![
            menu::StandardItem {
                label: "MyKey".into(),
                enabled: false,
                ..Default::default()
            }
            .into(),
            menu::MenuItem::Separator,
        ];

        items.extend(
            self.snapshot
                .lines()
                .into_iter()
                .map(|label| menu::StandardItem {
                    label,
                    enabled: false,
                    ..Default::default()
                })
                .map(Into::into),
        );

        items.extend([
            menu::MenuItem::Separator,
            menu::StandardItem {
                label: "Refresh Status".into(),
                activate: Box::new(|tray: &mut Self| tray.refresh_status_cache()),
                ..Default::default()
            }
            .into(),
            menu::StandardItem {
                label: "Quit".into(),
                activate: Box::new(|_| std::process::exit(0)),
                ..Default::default()
            }
            .into(),
        ]);

        items
    }
}

fn load_icons() -> Vec<Icon> {
    let img = match image::load_from_memory(LOGO_BYTES) {
        Ok(i) => i,
        Err(e) => {
            log::warn!("[tray] Failed to load logo PNG: {e}");
            return vec![];
        }
    };

    [16, 22, 32, 48, 64, 128]
        .iter()
        .map(|&size| encode_icon(&img, size))
        .collect()
}

fn encode_icon(img: &image::DynamicImage, size: u32) -> Icon {
    let resized = img.resize_exact(size, size, image::imageops::FilterType::Lanczos3);
    let rgba = resized.to_rgba8();

    let data: Vec<u8> = rgba
        .pixels()
        .flat_map(|p| {
            let [r, g, b, a] = p.0;
            [a, r, g, b]
        })
        .collect();

    Icon {
        width: size as i32,
        height: size as i32,
        data,
    }
}
