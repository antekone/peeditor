/* 
 * File:   Alloc.hpp
 * Author: antek
 *
 * Created on 22 lipiec 2008, 11:15
 */

#ifndef _ALLOC_HPP
#define	_ALLOC_HPP

template<typename T> class Alloc {
public:
	static T *anew() {
		return Alloc<T>::anew(1);
	}
	
	static T *anew(int size) {
		assert(size > 0);
		
		// cout << "so: " << sizeof(T) << endl;
		T *ptr = new T[size];
		assert(ptr);
		
		memset(ptr, 0, size * sizeof(T));
		return ptr;
	}
	
	static T **anewarray(int size) {
		assert(size > 0);
		
		T **arr = (T**) malloc(sizeof(T) * size);
		for(int i = 0; i < size; i++)
			arr[i] = new T;
		return arr;
	}
	
	static void adelete(T *ptr) {
		assert(ptr);
		
		delete [] ptr;
	}
	
	static void adeletearray(T **ptr, int n) {
		assert(ptr);
		
		for(int i = 0; i < n; i++) {
			assert(ptr[i]);
			delete ptr[i];
		}
		
		free(ptr);
	}
};

#endif	/* _ALLOC_HPP */

