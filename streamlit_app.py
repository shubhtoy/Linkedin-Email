import requests
import concurrent.futures
import pandas as pd
import streamlit as st
import base64
import chardet
from pathlib import Path

def get_email_by_linkedin(linkedin_url, _type="personal"):
    try:
        linkedin_id = linkedin_url.split("/")[-1]
        url = "https://kendoemailapp.com/emailbylinkedin"
        params = {
            "apikey": "5d00b489b9ad9342d8df232a",
            "linkedin": linkedin_id,
            "type": _type,
        }
        headers = {"accept": "application/json"}

        response = requests.get(url, params=params, headers=headers)

        if response.status_code == 200:
            # print(response.json(), response.status_code)
            if _type == "personal":
                email = response.json()["private_email"]
                return {"email": email, "url": linkedin_url}
            else:
                email = response.json()["work_email"]
                return {"email": email, "url": linkedin_url}
        elif response.status_code == 404 and _type == "personal":
            # print("Private not Found, Checking Work Email:", linkedin_id)
            result = get_email_by_linkedin(linkedin_url, _type="work")
            if result:
                return result
            else:
                return None
            # params["type"] = "work"
        elif response.status_code == 404 and _type == "work":
            # print("Work Email Not Found:", linkedin_id)
            return None
        else:
            print(f"Request failed with status code {response.status_code}.")
    except:
        return get_email_by_linkedin(linkedin_url, _type=_type)


def process_url(linkedinurl):
    return get_email_by_linkedin(linkedinurl)


def get_emails(urls, progress_bar):
    valid_data = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=9) as executor:
        futures = [executor.submit(process_url, url) for url in urls]

        # Create a spinner with a message
        spinner_text = "Scraping email addresses..."
        with st.spinner(spinner_text):
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                result = future.result()
                if result:
                    valid_data.append(result)
                progress = (i + 1) / len(urls)
                progress_bar.progress(progress)
    return valid_data


def main():
    # Add a title to the main window

    st.set_page_config(page_title="Linkedin Email Scraper", page_icon=":envelope:")
    st.title("Linkedin Email Scraper")
    st.write(
        """
    This app allows you to scrape Linkedin email addresses from a CSV file or text input. 

    **To Scrape email addresses from a CSV file:**

    1. Click on the "Upload CSV file" section in the sidebar.
    2. Select a CSV file containing Linkedin URl(s).
    3. Choose the column containing the URL(s).
    4. Click the "Get Email" button to start scraping.

    **To scrape email addresses from text input:**

    1. Click on the "Enter Linked URL" section in the sidebar.
    2. Enter a list of URL(s) separated by commas.
    3. Click the "Get Emails" button to start scraping.

    The Scraped email addresses will be displayed in a table below. You can select which columns to display using the dropdown menu. You can also download the Scraped email addresses as a CSV file by clicking the "Download CSV" button.

    """
    )
    # st.sidebar.title("Email Validator")

    if "valid_data" not in st.session_state:
        st.session_state.valid_data = []

    # Clear the session state variable
    # if st.sidebar.button("Clear", key="clear_button"):
    #     st.session_state.valid_data = []

    # Validate email addresses from uploaded CSV file
    st.sidebar.write("### Upload CSV file")
    uploaded_file = st.sidebar.file_uploader("Choose a CSV file", type="csv")
    if uploaded_file is not None:
        detected=chardet.detect(Path(uploaded_file.name).read_bytes())
        encoding=detected['encoding']
        df = pd.read_csv(uploaded_file,encoding=encoding)
        column_name = st.sidebar.selectbox("Select URL column", df.columns)

        # Show a "Validate Email" button and run validation when clicked
        if st.sidebar.button("Get Emails", key="get_emails_button"):
            # Show a spinner while the validation is in progress
            spinner = st.spinner("Getting email addresses...")

            # Validate the email addresses and store them in the session state variable
            progress_bar = st.progress(0)
            st.session_state.valid_data += get_emails(
                df[column_name].values.tolist(),
                progress_bar,
            )

    # Validate email addresses from text input
    st.sidebar.write("### Enter Linkedin URL")
    email_input = st.sidebar.text_input("Enter URL(s) (separated by comma)")
    if email_input:
        urls = [email.strip() for email in email_input.split(",")]

        # Show a "Validate Email" button and run validation when clicked
        if st.sidebar.button("Get Emails", key="get_emails_text_button"):
            # Show a spinner while the validation is in progress
            spinner = st.spinner("Validating email addresses...")

            # Validate the email addresses and store them in the session state variable
            progress_bar = st.progress(0)
            st.session_state.valid_data += get_emails(urls, progress_bar)

    # Show the validated email addresses
    if st.session_state.valid_data:
        st.write(f"Found {len(st.session_state.valid_data)} email addresses.")

        # Create a multiselect box to show/hide specific columns
        columns = st.session_state.valid_data[0].keys()
        visible_columns = st.multiselect(
            "Select columns to show", list(columns), default=list(columns)
        )

        # Show a table of the valid email addresses
        valid_data_df = pd.DataFrame(st.session_state.valid_data)[visible_columns]
        st.write(valid_data_df)

        # Add a download button to download the valid email addresses as a CSV file
        # csv = valid_data_df.to_csv(index=False)
        # b64 = base64.b64encode(csv.encode()).decode()
        csv = valid_data_df.to_csv(index=False)
        b64 = base64.b64encode(csv.encode()).decode()
        button_label = "Download CSV"
        button_download = st.download_button(
            label=button_label, data=csv, file_name="linkedin_emails.csv"
        )
        st.markdown(button_download, unsafe_allow_html=True)

    # Move the "Clear" button to the top of the sidebar
    st.sidebar.markdown("---")
    if st.sidebar.button("Clear", key="clear_button"):
        st.sidebar.empty()
        st.sidebar.empty()
        st.session_state.valid_data = []


if __name__ == "__main__":
    main()
