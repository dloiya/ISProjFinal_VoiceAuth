import streamlit as st


from PIL import Image
image = Image.open('pages/encrypted_passphrase_qr.png')
st.image(image, caption='Sample Image', use_column_width=True)

if st.button('Back'):
    st.switch_page("pages/piwhotemp.py")



