import { Router } from 'express';
import {
  addProductController,
  getProductByIdController,
  getAllProductsController,
  updateProductController,
  deleteProductController,
} from '@/api/controllers/products.controller';

const router = Router();

router.post('/add', addProductController);
router.get('/all', getAllProductsController);
router.get('/:productId', getProductByIdController); 
router.put('/update/:productId', updateProductController);
router.delete('/delete/:productId', deleteProductController);

export default router;
