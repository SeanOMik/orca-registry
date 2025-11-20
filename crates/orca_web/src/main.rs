use leptos::prelude::*;
use leptos::ev::SubmitEvent;
use leptos::html;
use leptos_router::components::*;
use leptos_router::path;
use leptos_use::use_cookie;

#[component]
pub fn Login() -> impl IntoView {
    let email_ref: NodeRef<html::Input> = NodeRef::new();
    let password_ref: NodeRef<html::Input> = NodeRef::new();

    /* let form_submit_action = Action::new_local(move |(email, password): &(String, String)| {
        let email = email.clone();
        let password = password.clone();
        async move {
            //let mut client = RestClient::new("instance.org");
            //client.login_user(&email, &password).await
        }
    });
    let login_result = form_submit_action.value();

    let form_submit = move |ev: SubmitEvent| {
        ev.prevent_default();

        let email = email_ref.get().unwrap().value();
        let password = password_ref.get().unwrap().value();
        form_submit_action.dispatch_local((email, password));
    };

    let error_message = move || {
        let login_result = login_result.read();
        match &*login_result {
            Some(Err(e)) => Some(format!("Failure to communicate with server:\n{:?}", e)),
            Some(Ok(Some(tkn))) => {
                let (_, set_session) =
                    use_cookie::<String, codee::string::FromToStringCodec>("session");
                set_session.set(Some(tkn.clone()));

                let navigate = leptos_router::hooks::use_navigate();
                navigate("/web/app", Default::default());

                None
            }
            Some(Ok(None)) => Some("Incorrect email or password!".to_string()),
            None => None,
        }
    }; */

    view! {
        <div class="flex items-center justify-center h-screen w-screen">
            <div class="p-8 rounded-lg shadow-lg bg-gray-200 dark:bg-surface-tonal-a20 ">
                <h2 class="text-2xl font-semibold text-center text-gray-800 dark:text-white mb-4">"Login"</h2>

                <form /* on:submit=form_submit */ class="flex flex-col gap-4">
                    <div>
                        <label for="username" class="block text-sm font-medium text-gray-700 dark:text-white">"Username"</label>
                        <input type="email" id="username" name="username" node_ref=email_ref class="w-full mt-1 px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-black" required />
                    </div>
                    <div>
                        <label for="password" class="block text-sm font-medium text-gray-700 dark:text-white">"Password"</label>
                        <input type="password" id="password" name="password" node_ref=password_ref class="w-full mt-1 px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-black" required />
                    </div>
                    /* <div class="flex justify-center text-red-500 text-sm">
                        {error_message}
                    </div> */
                    <button type="submit" class="w-full py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500">
                        "Login"
                    </button>
                </form>
                <div class="text-center mt-4">
                    <a href="#" class="text-sm text-blue-500 hover:text-blue-700">"Forgot your password?"</a>
                </div>
            </div>
        </div>
    }
}

#[component]
pub fn App() -> impl IntoView {
    view! {
        /* <Stylesheet id="leptos" href="/style/output.css"/> */
        // <Link rel="shortcut icon" type_="image/ico" href="/favicon.ico"/>
        <div class="flex h-screen w-screen bg-white dark:bg-surface-a20 dark:text-white">
            <Router>
                <Routes fallback=|| "Page not found.">
                    <Route
                        path=path!("/login")
                        view=Login
                    />
                </Routes>
            </Router>
        </div>
    }
}

fn main() {
    leptos::mount::mount_to_body(App)
}