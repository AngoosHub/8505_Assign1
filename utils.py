#!/usr/bin/env python3

"""
----------------------------------------------------------------------------------------------------
COMP 8505 BTech Network Security & Applications Development
Assignment 1:
    - Familiarize with Steganography and design a simple LSB steganography application.
Student:
    - Hung Yu (Angus) Lin, A01034410, Set 7J
----------------------------------------------------------------------------------------------------
utils.py
    - This module functions related to embedding and extracting the secret data from a
      steganography image.
----------------------------------------------------------------------------------------------------
"""

from PIL import Image
import numpy as np
import image, encryption

DELIMITER_FILENAME = "!F1L3N#ME%!".encode('utf-8')
DELIMITER_END = "!$T3GA_3ND%!".encode('utf-8')


def data_and_filename_to_binary(data, filename):
    encrypted_data = encryption.encrypt(data)
    stega_data = filename.encode('utf-8') + DELIMITER_FILENAME + encrypted_data + DELIMITER_END
    return data_to_binary(stega_data)


def data_to_binary(data):
    """

    :param data: Byte array
    :return: Bit array.
    """
    if type(data) == bytes or type(data) == np.ndarray:
        # Convert Bytes into a list of binaries.
        return ''.join([format(i, "08b") for i in data])

        # Non-comprehension version of the loop.
        # new_data = []
        # for i in data:
        #     new_data.append(format(i, "08b"))
        # bit_string = ''.join(new_data)
        # return bit_string
    else:
        raise TypeError(f"Data type is not Bytes. Data type: {type(data)}.")


def binary_to_data_and_filename(binary):
    delimiter_end = ''.join(data_to_binary(DELIMITER_END))
    delimiter_filename = ''.join(data_to_binary(DELIMITER_FILENAME))
    split_end = binary.split(delimiter_end, 1)
    if len(split_end) < 2:
        raise ValueError(f"No End of file Delimiter found, image does not contain Steganography.")

    split_filename = split_end[0].split(delimiter_filename, 1)
    if (len(split_filename)) < 2:
        raise ValueError(f"No Filename Delimiter found, Steganography embedding was incorrect.")

    filename = split_filename[0]
    data_temp = split_filename[1]
    data_en = binary_to_data(data_temp)
    data = encryption.decrypt(data_en)
    # return binary_to_data(filename), data
    return binary_to_data(filename), data_en # Skips Decrypt to show Encrypt works.


def binary_to_data(binary):
    # Splits binary string into a list of groups of 8.
    # binary_split_8 = [binary[i: i+8] for i in range(0, len(binary), 8)]

    # Non-Comprehension version of loop
    # new_data = []
    # for i in range(0, len(binary), 8):
    #     new_data.append(binary[i:i+8])
    # print(new_data)

    # Converts bitstring into byte array.
    # int.to_bytes(byte length, byteorder)
    # byteorder big means most significant bit at front not back.
    new_data = int(binary, 2).to_bytes((len(binary) + 7) // 8, byteorder='big')

    return new_data


def embed(img_array, secret_data, filename, lsb=1):
    secret_bitstring = data_and_filename_to_binary(secret_data, filename)

    # Check cover image large enough to hide data.
    # if len(secret_bitstring) > img_array.size:
    #     raise ValueError("Error, cover image too small to embed secret data. "
    #                      "Use bigger cover image or smaller secret file.")

    data_index = 0
    data_len = len(secret_bitstring)

    for pixel_rows in img_array:
        for pixel in pixel_rows:
            for i in range(len(pixel)):
                if data_index < data_len:
                    binary_val = format(pixel[i], "08b")
                    stega_data = secret_bitstring[data_index:data_index+lsb]
                    # while len(stega_data) < lsb:
                    #     # pad with 0 at end if remaining data less than number of LSB to embed.
                    #     stega_data += "0"
                    pixel[i] = int(binary_val[:-lsb] + stega_data, 2)
                    data_index += len(stega_data)
                else:
                    return img_array


def extract(img_array, lsb=1):
    delimiter_end = ''.join(data_to_binary(DELIMITER_END))

    binary_data = ""
    for pixel_rows in img_array:
        for pixel in pixel_rows:
            for i in range(len(pixel)):
                # Check if delimiter at end of current extracted binary data.
                if delimiter_end not in binary_data[-len(delimiter_end)-lsb:]:
                    binary_val = format(pixel[i], "08b")
                    # Slice out LSB embed at end.
                    binary_data += binary_val[-lsb:]
                    # print(binary_data)
                else:
                    return binary_to_data_and_filename(binary_data)

    return binary_to_data_and_filename(binary_data)


# Testing code:
# i_array = image.read_image("test.bmp")
# output = embed(i_array, b"hello world", "test.txt")
# with open("stega_array.txt", "w") as test1:
#     test1.write(str(i_array))
# image.save_image(output, "[Steg]test.bmp")

# i_array = image.read_image("[Steg]test.bmp")
# with open("secret_array.txt", "w") as test1:
#     test1.write(str(i_array))
# filename, byte_data = extract(i_array)
# print(filename)
# print(byte_data)


# secret_data = data_and_filename_to_binary(b"hello world", "test.txt")
# output = embed(i_array, secret_data)
# filename, byte_data = extract(output)
# print(filename)
# print(byte_data)







