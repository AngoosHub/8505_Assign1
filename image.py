#!/usr/bin/env python3

"""
----------------------------------------------------------------------------------------------------
COMP 8505 BTech Network Security & Applications Development
Assignment 1:
    - Familiarize with Steganography and design a simple LSB steganography application.
Student:
    - Hung Yu (Angus) Lin, A01034410, Set 7J
----------------------------------------------------------------------------------------------------
image.py
    - This module contains all image processing and manipulation functions.
----------------------------------------------------------------------------------------------------
"""

from PIL import Image
import numpy as np
# import cv2
# *** IMPORTANT: OpenCV and PyQt5 are incompatible, for future projects, pick one. ***


def read_image(image_path):
    # img_array = cv2.imread(image_path)
    # img_array = cv2.cvtColor(image_path, cv2.COLOR_BGR2BGRA)

    img = Image.open(image_path)
    img_rgb = img.convert('RGB')
    img_array = np.array(img_rgb)

    return img_array


def save_image(img_array, path):
    # cv2.imwrite(path, img_array)

    new_image = Image.fromarray(img_array)
    new_image.save(path)

