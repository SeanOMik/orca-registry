use leptos::{component, view, IntoView};

use leptos_router::{Router, Route, Routes};

use tracing_subscriber::fmt;
use tracing_subscriber_wasm::MakeConsoleWriter;

mod pages;

#[component]
fn App() -> impl IntoView {
    view! {
        <Router>
            <Routes>
                <Route path="/login" view=pages::Login />
                <Route path="/*any" view=|| view! { <p>"404 Not Found"</p> }/>
            </Routes>
        </Router>
    }
}

fn main() {
    fmt()
        .with_writer(
            MakeConsoleWriter::default()
                .map_trace_level_to(tracing::Level::DEBUG),
        )
        .without_time()
        .init();
    //console_error_panic_hook::set_once();

    leptos::mount_to_body(|| view! { <App/> })
}