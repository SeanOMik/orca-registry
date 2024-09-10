use leptos::{component, create_signal, view, CollectView, IntoView, ReadSignal, Signal, SignalUpdate};
use thaw::{Button, ButtonVariant};

#[component]
fn ProgressBar(
    #[prop(default = 100)]
    max: u16,
    // this isn't a ReadSignal<i32> so that `double_count` can also be accepted.
    //progress: impl Fn() -> i32 + 'static,
    #[prop(into)]
    progress: Signal<i32>
) -> impl IntoView {
    view! {
        <progress
            max=max
            value=progress
        />
        <br/>
    }
}

#[component]
fn App() -> impl IntoView {
    // create a list of 5 signals
    let length = 5;
    let counters = (1..=length).map(|idx| create_signal(idx));

    // each item manages a reactive view
    // but the list itself will never change
    let counter_buttons = counters
        .map(|(count, set_count)| {
            view! {
                <li>
                    <Button variant=ButtonVariant::Primary
                        on:click=move |_| set_count.update(|n| *n += 1)
                    >
                        {count}
                    </Button>
                </li>
            }
        })
        .collect_view();

    view! {
        <ul>{counter_buttons}</ul>
    }
}

fn main() {
    leptos::mount_to_body(|| view! { <App/> })
}