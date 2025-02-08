import { Request, Response, NextFunction } from 'express';
import {
  addProduct,
  getProductById,
  getAllProducts,
  updateProduct,
  deleteProduct,
} from '@/api/services/products.service';

/**
 * Controller to add a new product.
 */
export const addProductController = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const product = await addProduct(req.body);
    res.status(201).json({ success: true, data: product });
  } catch (error) {
    next(error);
  }
};

/**
 * Controller to get a product by ID.
 */
export const getProductByIdController = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { productId } = req.params;
    const product = await getProductById(productId);

    if (!product) {
      res.status(404).json({ success: false, message: 'Product not found' });
      return;
    }

    res.status(200).json({ success: true, data: product });
  } catch (error) {
    next(error);
  }
};

/**
 * Controller to get all products.
 */
export const getAllProductsController = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const products = await getAllProducts();
    res.status(200).json({ success: true, data: products });
  } catch (error) {
    next(error);
  }
};

/**
 * Controller to update a product by ID.
 */
export const updateProductController = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { productId } = req.params;
    const updatedProduct = await updateProduct(productId, req.body);

    if (!updatedProduct) {
      res.status(404).json({ success: false, message: 'Product not found or no changes made' });
      return;
    }

    res.status(200).json({ success: true, data: updatedProduct });
  } catch (error) {
    next(error);
  }
};

/**
 * Controller to delete a product by ID.
 */
export const deleteProductController = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { productId } = req.params;
    const deletedProduct = await deleteProduct(productId);

    if (!deletedProduct) {
      res.status(404).json({ success: false, message: 'Product not found' });
      return;
    }

    res.status(200).json({ success: true, message: 'Product deleted successfully', data: deletedProduct });
  } catch (error) {
    next(error);
  }
};
