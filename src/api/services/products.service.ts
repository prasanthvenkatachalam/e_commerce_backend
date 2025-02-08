import pool from '@/db/config';
import { Product } from '@/types/products.types';
import { CONSTANTS } from '@/utils/constants';

/**
 * Service to add a new product.
 */
export const addProduct = async (
  productData: Omit<Product, 'id' | 'created_at' | 'updated_at'>
): Promise<Product> => {
  try {
    const {
      category_id,
      name,
      slug,
      description,
      base_price,
      sku_prefix,
      sku,
      images,
      is_active,
      variants,
    } = productData;

    // Restrict image upload count
    const maxImageCount = Number(CONSTANTS.MAX_IMAGE_UPLOAD_COUNT) || 4;
    const limitedImages = (images ?? []).slice(0, maxImageCount);

    // Insert the product into the database
    const result = await pool.query(
      `
        INSERT INTO product_service.products (
          category_id,
          name,
          slug,
          description,
          base_price,
          sku_prefix,
          sku,
          images,
          is_active
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text[], $9)
        RETURNING *;
      `,
      [category_id, name, slug, description, base_price, sku_prefix, sku, limitedImages, is_active]
    );

    const productId = result.rows[0].id;

    // Insert product variants if provided
    if (variants && variants.length > 0) {
      const variantInsertPromises = variants.map((variant) =>
        pool.query(
          `
            INSERT INTO product_service.product_variants (
              product_id,
              internal_sku,
              display_sku,
              attributes,
              price_adjustment,
              stock_quantity,
              low_stock_threshold,
              optimal_stock,
              weight,
              dimensions,
              is_active
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
          `,
          [
            productId,
            variant.internal_sku,
            variant.display_sku,
            variant.attributes,
            variant.price_adjustment,
            variant.quantity,
            variant.low_stock_threshold,
            variant.optimal_stock,
            variant.weight,
            variant.dimensions,
            variant.is_active,
          ]
        )
      );
      await Promise.all(variantInsertPromises);
    }

    return result.rows[0];
  } catch (error) {
    console.error('Error adding product:', error);
    throw error;
  }
};

/**
 * Service to retrieve a product by ID.
 */
export const getProductById = async (id: string): Promise<Product | null> => {
  try {
    const result = await pool.query<Product>(
      `SELECT * FROM product_service.products WHERE id = $1;`,
      [id]
    );
    return result.rows[0] || null;
  } catch (error) {
    console.error('Error fetching product by ID:', error);
    throw error;
  }
};

/**
 * Service to retrieve all products.
 */
export const getAllProducts = async (): Promise<Product[]> => {
  try {
    const result = await pool.query<Product>(`SELECT * FROM product_service.products;`);
    return result.rows;
  } catch (error) {
    console.error('Error fetching all products:', error);
    throw error;
  }
};

/**
 * Service to update an existing product.
 */
export const updateProduct = async (
  id: string,
  productData: Partial<Omit<Product, 'id' | 'created_at' | 'updated_at'>>
): Promise<Product | null> => {
  try {
    const keys = Object.keys(productData);
    if (keys.length === 0) return null; // No updates needed

    const setClauses = keys.map((key, index) => `${key} = $${index + 1}`).join(', ');

    const result = await pool.query<Product>(
      `
        UPDATE product_service.products
        SET ${setClauses}
        WHERE id = $${keys.length + 1}
        RETURNING *;
      `,
      [...Object.values(productData), id]
    );

    return result.rows[0] || null;
  } catch (error) {
    console.error('Error updating product:', error);
    throw error;
  }
};

/**
 * Service to delete a product by ID.
 */
export const deleteProduct = async (id: string): Promise<Product | null> => {
  try {
    const result = await pool.query<Product>(
      `DELETE FROM product_service.products WHERE id = $1 RETURNING *;`,
      [id]
    );

    if (result.rowCount === 0) {
      console.warn(`Product with ID ${id} not found.`);
      return null;
    }

    return result.rows[0];
  } catch (error) {
    console.error('Error deleting product:', error);
    throw error;
  }
};
