/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Resolves an image reference to its URL string. A VC image may be a bare URL
 * string or an `IImageObject` (`{ id, type }`) whose `id` is the URL. Returns
 * `null` (not `''`) when there is no usable image, matching DCW's convention.
 */
import type { IImageObject } from '@interop/data-integrity-core'

function isImageObject(obj: unknown): obj is IImageObject {
  return typeof obj === 'object' && obj !== null && 'id' in obj && 'type' in obj
}

/**
 * The URL string of an image reference (the object's `id`, or the string
 * itself), or `null` when absent.
 *
 * @param image {IImageObject | string | null | undefined}
 * @returns {string | null}
 */
export function imageSourceFrom(
  image?: IImageObject | string | null
): string | null {
  if (image === undefined || image === null) {
    return null
  }
  if (isImageObject(image)) {
    return image.id
  }
  if (typeof image === 'string') {
    return image
  }
  return null
}
